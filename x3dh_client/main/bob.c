#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <cJSON.h>
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "common.h"
#include "http_client.h"
#include "freertos/FreeRTOS.h" // vTaskDelay()
#include "freertos/task.h"

static const char *TAG = "bob";

// --- Key Paths (NVS Keys) ---
#define BOB_USERNAME "bob"
// NVS keys are max 15 chars
#define BOB_IK_PRIV_FILE "bob_ik_priv"
#define BOB_IK_PUB_FILE "bob_ik_pub"
#define BOB_SPK_PRIV_FILE "bob_spk_priv"
#define BOB_SPK_PUB_FILE "bob_spk_pub"
#define BOB_OPK_PRIV_PREFIX "opk_" // e.g., opk_1
#define BOB_SK_PREFIX "sk_with_" // e.g., sk_with_alice

#define URL_BUFFER_SIZE 256
#define SHARED_KEY_SIZE 32
#define SIGNATURE_NONCE_SIZE 64
#define KDF_INPUT_MAX_SIZE 160
#define NUM_OPKS 10 // Number of OPKs to generate

/**
 * @brief Get the NVS key for the shared key file.
 * @param path_buf Buffer to store the NVS key.
 * @param buf_len Length of the buffer.
 * @param recipient The recipient's username.
 */
void get_sk_path(char *path_buf, size_t buf_len, const char *recipient) {
    snprintf(path_buf, buf_len, "%s%s", BOB_SK_PREFIX, recipient);
}

/**
 * @brief Get the NVS key for the OPK private key.
 * @param path_buf Buffer to store the NVS key.
 * @param buf_len Length of the buffer.
 * @param key_id The OPK ID number.
 */
void get_opk_path(char *path_buf, size_t buf_len, int key_id) {
    // Format: "opk_1", "opk_2", etc.
    snprintf(path_buf, buf_len, "%s%d", BOB_OPK_PRIV_PREFIX, key_id);
}

/**
 * @brief Erase an NVS key.
 * @param key The NVS key to erase.
 * @return 0 on success, -1 on failure.
 */
int nvs_erase_key_str(const char *key) {
    nvs_handle_t nvs_handle;
    esp_err_t err;

    err = nvs_open(NVS_KEY_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
        return -1;
    }

    err = nvs_erase_key(nvs_handle, key);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) erasing key '%s'!", esp_err_to_name(err), key);
        nvs_close(nvs_handle);
        return -1;
    }

    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) committing NVS erase!", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return -1;
    }

    nvs_close(nvs_handle);
    return 0;
}

// --- 1. Bob Register ---
int bob_register() {
    ESP_LOGI(TAG, "--- Bob: Registering ---");

    if (nvs_key_exists(BOB_IK_PRIV_FILE)) {
        ESP_LOGW(TAG, "WARNING: Keys already exist.");
        short int c, extra;
        while(1){
            printf("Are you sure you want to overwrite them? (y/n): ");
            fflush(stdout); 
            
            c = -1; // Reset c

            // Get the first valid character
            while(1) {
                c = fgetc(stdin);
                if (c < 0) {
                    vTaskDelay(pdMS_TO_TICKS(50));
                    continue;
                }
                if (c == '\n' || c == '\r') {
                    break; // Will re-print prompt
                }
                break; // Got a character
            }
            
            // If user just pressed Enter, re-print the prompt
            if (c == '\n' || c == '\r') {
                continue; 
            }

            // Clear the rest of the line
            do {
                extra = fgetc(stdin);
                if (extra < 0) {
                    vTaskDelay(pdMS_TO_TICKS(10));
                }
            } while (extra != '\n' && extra != EOF);

            
            if (c == 'y' || c == 'Y') {
                ESP_LOGW(TAG, "\nProceeding with re-registration...\n");
                break;
            }
            
            if (c == 'n' || c == 'N') {
                ESP_LOGW(TAG, "\nNew registration aborted.\n");
                return -1;
            }
            
            ESP_LOGW(TAG, "\nInvalid input. Please enter 'y' or 'n'.\n");
        }
    }

    unsigned char ik_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char ik_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char spk_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char spk_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char signature[crypto_sign_ed25519_BYTES];
    
    char *ik_pub_b64 = NULL;
    char *spk_pub_b64 = NULL;
    char *sig_b64 = NULL;
    cJSON *ik_data = NULL;
    cJSON *bundle_data = NULL;
    cJSON *opks_json_list = NULL;
    ResponseInfo resp = {0};
    short int ret = -1;

    // 1a. Generate Identity Key (IK)
    randombytes_buf(ik_priv, sizeof(ik_priv));
    priv_to_curve25519_pub(ik_pub, ik_priv);
    if (nvs_write_blob_str(BOB_IK_PRIV_FILE, ik_priv, sizeof(ik_priv)) != 0 ||
        nvs_write_blob_str(BOB_IK_PUB_FILE, ik_pub, sizeof(ik_pub)) != 0) {
        ESP_LOGE(TAG, "Failed to write Bob's IK to NVS.");
        goto cleanup;
    }
    
    // 1b. Register IK with Server
    ik_pub_b64 = b64_encode(ik_pub, sizeof(ik_pub));
    if (!ik_pub_b64) goto cleanup;
    
    ik_data = cJSON_CreateObject();
    cJSON_AddStringToObject(ik_data, "username", BOB_USERNAME);
    cJSON_AddStringToObject(ik_data, "ik_b64", ik_pub_b64);
    
    if (http_post_json(SERVER_URL "/register_ik", ik_data, &resp) != 0 || (resp.http_code != 201)) {
        ESP_LOGE(TAG, "Failed to register IK with server. Code: %ld", resp.http_code);
        ESP_LOGE(TAG, "Server response: %s", resp.body ? resp.body : "N/A");
        goto cleanup;
    }
    ESP_LOGI(TAG, "Bob registered IK successfully.");
    cleanup_response(&resp);

    // 2. Generate Signed Prekey (SPK)
    randombytes_buf(spk_priv, sizeof(spk_priv));
    priv_to_curve25519_pub(spk_pub, spk_priv);

    // 3. Sign SPK with IK's private key
    uint8_t sign_nonce[SIGNATURE_NONCE_SIZE];
    randombytes_buf(sign_nonce, SIGNATURE_NONCE_SIZE);
    unsigned char bob_private_signing_key[crypto_scalarmult_curve25519_BYTES];
    priv_force_sign(bob_private_signing_key, ik_priv, 0);
    ed25519_priv_sign(signature, bob_private_signing_key, spk_pub, crypto_scalarmult_curve25519_BYTES, sign_nonce);
    ESP_LOGI(TAG, "SPK signed with IK successfully.");

    // 4. Save local SPK to NVS
    if (nvs_write_blob_str(BOB_SPK_PRIV_FILE, spk_priv, sizeof(spk_priv)) != 0 ||
        nvs_write_blob_str(BOB_SPK_PUB_FILE, spk_pub, sizeof(spk_pub)) != 0) {
        ESP_LOGE(TAG, "Failed to write Bob's SPK to NVS."); goto cleanup;
    }

    // 5. Generate One-Time Prekeys (OPKs)
    ESP_LOGI(TAG, "Generating %d One-Time Prekeys...", NUM_OPKS);
    opks_json_list = cJSON_CreateArray();
    if (!opks_json_list) {
        ESP_LOGE(TAG, "Failed to create cJSON array for OPKs");
        goto cleanup;
    }

    for (int i = 0; i < NUM_OPKS; i++) {
        unsigned char opk_priv[crypto_scalarmult_curve25519_BYTES];
        unsigned char opk_pub[crypto_scalarmult_curve25519_BYTES];
        
        randombytes_buf(opk_priv, sizeof(opk_priv));
        priv_to_curve25519_pub(opk_pub, opk_priv);
        
        // Save private key locally to NVS
        char opk_priv_path[32];
        get_opk_path(opk_priv_path, sizeof(opk_priv_path), i);
        if (nvs_write_blob_str(opk_priv_path, opk_priv, sizeof(opk_priv)) != 0) {
            ESP_LOGE(TAG, "Failed to write OPK %d to NVS", i);
            goto cleanup;
        }
        
        // Add public key to JSON list for upload
        char *opk_pub_b64 = b64_encode(opk_pub, sizeof(opk_pub));
        cJSON *opk_json = cJSON_CreateObject();
        cJSON_AddNumberToObject(opk_json, "id", i);
        cJSON_AddStringToObject(opk_json, "key", opk_pub_b64);
        cJSON_AddItemToArray(opks_json_list, opk_json);
        
        free(opk_pub_b64);
        sodium_memzero(opk_priv, sizeof(opk_priv));
    }
    ESP_LOGI(TAG, "Generated and saved %d OPKs.", NUM_OPKS);

    // 6. Create Bundle JSON to upload
    spk_pub_b64 = b64_encode(spk_pub, sizeof(spk_pub));
    sig_b64 = b64_encode(signature, sizeof(signature));
    if (!spk_pub_b64 || !sig_b64) goto cleanup;

    bundle_data = cJSON_CreateObject();
    cJSON_AddStringToObject(bundle_data, "username", BOB_USERNAME);
    cJSON_AddStringToObject(bundle_data, "spk_b64", spk_pub_b64);
    cJSON_AddStringToObject(bundle_data, "spk_sig_b64", sig_b64);
    cJSON_AddItemToObject(bundle_data, "opks_b64", opks_json_list);
    
    // 7. Upload Bundle to server
    if (http_post_json(SERVER_URL "/register_bundle", bundle_data, &resp) != 0 || resp.http_code != 201) {
        ESP_LOGE(TAG, "Failed to register bundle with server. Code: %ld", resp.http_code);
        ESP_LOGE(TAG, "Server response: %s", resp.body ? resp.body : "N/A");
        goto cleanup;
    }

    ESP_LOGI(TAG, "Bob's bundle registered successfully.");
    ret = 0;

cleanup:
    sodium_memzero(ik_priv, sizeof(ik_priv));
    sodium_memzero(spk_priv, sizeof(spk_priv));
    sodium_memzero(bob_private_signing_key, sizeof(bob_private_signing_key));
    free(ik_pub_b64);
    free(spk_pub_b64);
    free(sig_b64);
    if (ik_data) cJSON_Delete(ik_data);
    if (bundle_data) cJSON_Delete(bundle_data);
    cleanup_response(&resp);
    return ret;
}

// --- 2. Bob Read Initial X3DH Message ---
int bob_read_initial_message() {
    ESP_LOGI(TAG, "--- Bob: Checking for initial message ---");
    
    unsigned char ik_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char spk_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char opk_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char alice_ik_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char alice_ek_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char ad[crypto_scalarmult_curve25519_BYTES * 2];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char sk[SHARED_KEY_SIZE];
    memset(sk, 0, sizeof(sk));
    
    unsigned char kdf_input[KDF_INPUT_MAX_SIZE];
    size_t kdf_input_len = 0;

    cJSON *msg = NULL;
    ResponseInfo resp = {0};
    unsigned char *ciphertext = NULL;
    unsigned char *decrypted_msg = NULL;
    short int ret = -1;
    short int has_opk = 0;
    short int opk_id = -1;
    char opk_priv_path[32] = {0};

    // 1. Fetch message from server
    char url_buf[URL_BUFFER_SIZE];
    snprintf(url_buf, URL_BUFFER_SIZE, SERVER_URL "/get_initial_message/%s", BOB_USERNAME);

    if (http_get(url_buf, &resp) != 0) {
        ESP_LOGE(TAG, "Failed to connect to server.");
        goto cleanup;
    }
    
    if (resp.http_code == 404) {
        ESP_LOGI(TAG, "No new initial messages for Bob.");
        ret = 0;
        goto cleanup;
    }
    
    if (resp.http_code != 200) {
        ESP_LOGE(TAG, "Failed to get message for Bob. Code: %ld", resp.http_code);
        ESP_LOGE(TAG, "Server response: %s", resp.body ? resp.body : "N/A");
        goto cleanup;
    }
    ESP_LOGI(TAG, "Received initial message from server.");

    // 2. Parse the message
    msg = cJSON_Parse(resp.body);
    if (!msg) {
        ESP_LOGE(TAG, "Failed to parse message JSON");
        goto cleanup;
    }
    
    const cJSON *j_from_user = cJSON_GetObjectItemCaseSensitive(msg, "from_user");
    const cJSON *j_ik_b64 = cJSON_GetObjectItemCaseSensitive(msg, "ik_b64");
    const cJSON *j_ek_b64 = cJSON_GetObjectItemCaseSensitive(msg, "ek_b64");
    const cJSON *j_opk_id = cJSON_GetObjectItemCaseSensitive(msg, "opk_id");
    const cJSON *j_ciphertext_b64 = cJSON_GetObjectItemCaseSensitive(msg, "ciphertext_b64");
    const cJSON *j_ad_b64 = cJSON_GetObjectItemCaseSensitive(msg, "ad_b64");
    const cJSON *j_nonce_b64 = cJSON_GetObjectItemCaseSensitive(msg, "nonce_b64");
    
    if (!cJSON_IsString(j_from_user) || !cJSON_IsString(j_ik_b64) || !cJSON_IsString(j_ek_b64) ||
        !cJSON_IsNumber(j_opk_id) || !cJSON_IsString(j_ciphertext_b64) ||
        !cJSON_IsString(j_ad_b64) || !cJSON_IsString(j_nonce_b64)) {
        ESP_LOGE(TAG, "Failed to unpack message JSON (missing/wrong types)");
        goto cleanup;
    }

    const char *from_user = j_from_user->valuestring;
    const char *ik_b64 = j_ik_b64->valuestring;
    const char *ek_b64 = j_ek_b64->valuestring;
    const char *ciphertext_b64 = j_ciphertext_b64->valuestring;
    const char *ad_b64 = j_ad_b64->valuestring;
    const char *nonce_b64 = j_nonce_b64->valuestring;
    opk_id = j_opk_id->valueint;

    ESP_LOGI(TAG, "Processing initial message from: %s", from_user);

    // 3. Load Bob's private keys from NVS
    if (nvs_read_blob_str(BOB_IK_PRIV_FILE, ik_priv, sizeof(ik_priv)) != 0 ||
        nvs_read_blob_str(BOB_SPK_PRIV_FILE, spk_priv, sizeof(spk_priv)) != 0) {
        ESP_LOGE(TAG, "Failed to read Bob's local keys from NVS. Have you registered?");
        goto cleanup;
    }
    
    has_opk = (opk_id != -1);
    if (has_opk) {
        get_opk_path(opk_priv_path, sizeof(opk_priv_path), opk_id);
        if (nvs_read_blob_str(opk_priv_path, opk_priv, sizeof(opk_priv)) != 0) {
            ESP_LOGE(TAG, "Failed to read OPK %d private key from NVS!", opk_id);
            goto cleanup;
        }
        ESP_LOGI(TAG, "Loaded OPK %d private key.", opk_id);
    }

    // 4. Decode Alice's public keys, AD, and nonce
    if (b64_decode(ik_b64, alice_ik_pub, sizeof(alice_ik_pub)) != sizeof(alice_ik_pub) ||
        b64_decode(ek_b64, alice_ek_pub, sizeof(alice_ek_pub)) != sizeof(alice_ek_pub) ||
        b64_decode(ad_b64, ad, sizeof(ad)) != sizeof(ad) ||
        b64_decode(nonce_b64, nonce, sizeof(nonce)) != sizeof(nonce)) {
        ESP_LOGE(TAG, "Failed to decode base64 keys/AD/nonce from message.");
        goto cleanup;
    }

    // 5. Perform DH calculations
    unsigned char dh1[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh2[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh3[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh4[crypto_scalarmult_curve25519_BYTES];

    if (x25519(dh1, spk_priv, alice_ik_pub) != 0 ||
        x25519(dh2, ik_priv, alice_ek_pub) != 0 ||
        x25519(dh3, spk_priv, alice_ek_pub) != 0) {
        ESP_LOGE(TAG, "DH calculation failed.");
        goto cleanup;
    }
    
    if (has_opk) {
        if (x25519(dh4, opk_priv, alice_ek_pub) != 0) {
            ESP_LOGE(TAG, "DH4 calculation failed.");
            goto cleanup;
        }
    }

    // 6. Concatenate DH outputs
    unsigned char f_padding[32];
    memset(f_padding, 0xFF, sizeof(f_padding));

    kdf_input_len = 32 + 32 + 32 + 32; // F + DH1 + DH2 + DH3
    memcpy(kdf_input, f_padding, 32);
    memcpy(kdf_input + 32, dh1, 32);
    memcpy(kdf_input + 64, dh2, 32);
    memcpy(kdf_input + 96, dh3, 32);
    if (has_opk) {
        memcpy(kdf_input + 128, dh4, 32);
        kdf_input_len += 32;
    }

    // 7. Derive Shared Key (SK)
    if (hkdf(sk, sizeof(sk), kdf_input, kdf_input_len, X3DH_INFO_STRING) != 0) {
        ESP_LOGE(TAG, "KDF failed.");
        goto cleanup;
    }

    ESP_LOGI(TAG, "Shared Key (SK) computed successfully (Bob).");

    // Save SK to NVS
    char sk_path[64];
    get_sk_path(sk_path, sizeof(sk_path), from_user);
    if (nvs_write_blob_str(sk_path, sk, sizeof(sk)) != 0) {
        ESP_LOGE(TAG, "CRITICAL: Failed to save shared key to NVS key %s!", sk_path);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Shared key saved to NVS key: %s", sk_path);

    // 8. Decrypt message
    size_t ciphertext_len = 0;
    ciphertext = b64_decode_ex(ciphertext_b64, 0, &ciphertext_len);
    if (!ciphertext) {
        ESP_LOGE(TAG, "Failed to decode ciphertext.");
        goto cleanup;
    }

    unsigned long long decrypted_len;
    decrypted_msg = malloc(ciphertext_len); // Decrypted len <= Ciphertext len
    if (!decrypted_msg) {
        ESP_LOGE(TAG, "Failed to malloc for decrypted message.");
        goto cleanup;
    }
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted_msg, &decrypted_len,
            NULL, // nsec (not used)
            ciphertext, ciphertext_len,
            ad, sizeof(ad), // Associated Data
            nonce, sk) != 0) {
        ESP_LOGE(TAG, "!!! DECRYPTION FAILED! Invalid key or tampered message. !!!");
        goto cleanup;
    }
    
    decrypted_msg[decrypted_len] = '\0';
    printf("--- Initial Message Received ---\n");
    printf("[%s]: %s\n", from_user, (char *)decrypted_msg);
    printf("--------------------------------\n");
    ret = 0;

cleanup:
    sodium_memzero(ik_priv, sizeof(ik_priv));
    sodium_memzero(spk_priv, sizeof(spk_priv));
    sodium_memzero(opk_priv, sizeof(opk_priv));
    sodium_memzero(kdf_input, sizeof(kdf_input));
    sodium_memzero(sk, sizeof(sk));
    if (msg) cJSON_Delete(msg);
    cleanup_response(&resp);
    free(ciphertext);
    free(decrypted_msg);
    
    // Delete the OPK private key from NVS
    if (has_opk && strlen(opk_priv_path) > 0) {
        if (nvs_erase_key_str(opk_priv_path) == 0) {
             ESP_LOGI(TAG, "Used OPK %d (key: %s) private key deleted.", opk_id, opk_priv_path);
        } else {
             ESP_LOGW(TAG, "Warning: Failed to delete OPK private key %s", opk_priv_path);
        }
    }
    return ret;
}

// --- 3. Bob Send Chat Message (Post-X3DH) ---
int bob_send_chat_message(const char *recipient) {
    // 1. Load the shared key
    unsigned char sk[SHARED_KEY_SIZE];
    char sk_path[64];
    get_sk_path(sk_path, sizeof(sk_path), recipient);

    if (nvs_read_blob_str(sk_path, sk, sizeof(sk)) != 0) {
        ESP_LOGE(TAG, "No shared key found for %s. Run 'read_init' first.", recipient);
        return -1;
    }
    
    // 2. Get message from stdin
    printf("Enter message: ");
    fflush(stdout);
    char *message_text = read_message_from_stdin();
    if (!message_text || strlen(message_text) == 0) {
        ESP_LOGW(TAG, "No message entered. Aborting.");
        free(message_text);
        sodium_memzero(sk, sizeof(sk));
        return -1;
    }
    
    // 3. Encrypt message
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned long long ciphertext_len = strlen(message_text) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        ESP_LOGE(TAG, "Failed to malloc for ciphertext");
        free(message_text);
        sodium_memzero(sk, sizeof(sk));
        return -1;
    }

    crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
        (const unsigned char *)message_text, strlen(message_text),
        NULL, 0, // No Associated Data
        NULL, nonce, sk);
    
    free(message_text);
    
    // 4. Encode for JSON
    char *ciphertext_b64 = b64_encode(ciphertext, ciphertext_len);
    char *nonce_b64 = b64_encode(nonce, sizeof(nonce));
    free(ciphertext);
    
    if (!ciphertext_b64 || !nonce_b64) {
        ESP_LOGE(TAG, "Failed to b64-encode chat message.");
        free(ciphertext_b64);
        free(nonce_b64);
        sodium_memzero(sk, sizeof(sk));
        return -1;
    }
    
    // 5. Pack JSON and send to server
    cJSON *msg_data = cJSON_CreateObject();
    cJSON_AddStringToObject(msg_data, "from", BOB_USERNAME);
    cJSON_AddStringToObject(msg_data, "to", recipient);
    cJSON_AddStringToObject(msg_data, "ciphertext_b64", ciphertext_b64);
    cJSON_AddStringToObject(msg_data, "nonce_b64", nonce_b64);

    ResponseInfo resp = {0};
    if (http_post_json(SERVER_URL "/send_chat_message", msg_data, &resp) != 0 || resp.http_code != 201) {
        ESP_LOGE(TAG, "Failed to send chat message to server. Code: %ld", resp.http_code);
        ESP_LOGE(TAG, "Server response: %s", resp.body ? resp.body : "N/A");
    } else {
        ESP_LOGI(TAG, "Message sent.");
    }
    
    // 6. Cleanup
    free(ciphertext_b64);
    free(nonce_b64);
    cJSON_Delete(msg_data);
    cleanup_response(&resp);
    sodium_memzero(sk, sizeof(sk));
    return 0;
}

// --- 4. Bob Read Chat Messages (Post-X3DH) ---
int bob_read_chat_messages(const char *sender) {
    // 1. Load the shared key
    unsigned char sk[SHARED_KEY_SIZE];
    char sk_path[64];
    get_sk_path(sk_path, sizeof(sk_path), sender);

    if (nvs_read_blob_str(sk_path, sk, sizeof(sk)) != 0) {
        ESP_LOGE(TAG, "No shared key found for %s. Cannot decrypt messages.", sender);
        return -1;
    }
    
    // 2. Fetch messages from server
    char url_buf[URL_BUFFER_SIZE];
    snprintf(url_buf, URL_BUFFER_SIZE, SERVER_URL "/get_chat_messages/%s/from/%s", BOB_USERNAME, sender);
    ResponseInfo resp = {0};
    if (http_get(url_buf, &resp) != 0 || resp.http_code != 200) {
        ESP_LOGE(TAG, "Failed to get chat messages. Code: %ld", resp.http_code);
        ESP_LOGE(TAG, "Server response: %s", resp.body ? resp.body : "N/A");
        sodium_memzero(sk, sizeof(sk));
        cleanup_response(&resp);
        return -1;
    }
    
    // 3. Parse the message list
    cJSON *msg_list = cJSON_Parse(resp.body);
    if (!msg_list) {
        ESP_LOGE(TAG, "Failed to parse message list JSON");
        sodium_memzero(sk, sizeof(sk));
        cleanup_response(&resp);
        return -1;
    }
    
    if (!cJSON_IsArray(msg_list)) {
        ESP_LOGE(TAG, "Server response is not a JSON array.");
        cJSON_Delete(msg_list);
        sodium_memzero(sk, sizeof(sk));
        cleanup_response(&resp);
        return -1;
    }
    
    int count = cJSON_GetArraySize(msg_list);
    if (count == 0) {
        ESP_LOGI(TAG, "No new messages from %s.", sender);
        cJSON_Delete(msg_list);
        sodium_memzero(sk, sizeof(sk));
        cleanup_response(&resp);
        return 0;
    }
    
    ESP_LOGI(TAG, "--- Received %d new message(s) from %s ---", count, sender);
    
    // 4. Iterate, decode, and decrypt
    cJSON *msg = NULL;
    cJSON_ArrayForEach(msg, msg_list) {
        const cJSON *j_ciphertext_b64 = cJSON_GetObjectItemCaseSensitive(msg, "ciphertext_b64");
        const cJSON *j_nonce_b64 = cJSON_GetObjectItemCaseSensitive(msg, "nonce_b64");
        
        if (!cJSON_IsString(j_ciphertext_b64) || !cJSON_IsString(j_nonce_b64)) {
            ESP_LOGE(TAG, "Failed to unpack message.");
            continue;
        }

        const char *ciphertext_b64 = j_ciphertext_b64->valuestring;
        const char *nonce_b64 = j_nonce_b64->valuestring;

        // Decode
        size_t ciphertext_len = 0;
        unsigned char *ciphertext = b64_decode_ex(ciphertext_b64, 0, &ciphertext_len);
        
        unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        if (b64_decode(nonce_b64, nonce, sizeof(nonce)) != sizeof(nonce)) {
            ESP_LOGE(TAG, "Failed to decode nonce for message.");
            free(ciphertext);
            continue;
        }
        
        if (!ciphertext) {
            ESP_LOGE(TAG, "Failed to decode ciphertext for message.");
            continue;
        }
        
        // Decrypt
        unsigned long long decrypted_len;
        unsigned char *decrypted_msg = malloc(ciphertext_len);
        if (!decrypted_msg) {
             ESP_LOGE(TAG, "Failed to malloc for decrypted message.");
             free(ciphertext);
             continue;
        }
        
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted_msg, &decrypted_len,
                NULL, // nsec (not used)
                ciphertext, ciphertext_len,
                NULL, 0, // No Associated Data
                nonce, sk) != 0) {
            ESP_LOGE(TAG, "[Message: DECRYPTION FAILED!]");
        } else {
            decrypted_msg[decrypted_len] = '\0';
            printf("[%s]: %s\n", sender, (char *)decrypted_msg);
        }
        
        free(ciphertext);
        free(decrypted_msg);
    }
    
    printf("------------------------------------------\n");
    cJSON_Delete(msg_list);
    sodium_memzero(sk, sizeof(sk));
    cleanup_response(&resp);
    return 0;
}