#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <cJSON.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "common.h"
#include "http_client.h"
#include "freertos/FreeRTOS.h" // vTaskDelay()
#include "freertos/task.h"

static const char *TAG = "alice";

// --- Key Paths (NVS Keys) ---
#define ALICE_USERNAME "alice"
// NVS keys are max 15 chars
#define ALICE_IK_PRIV_FILE "alice_ik_priv"
#define ALICE_IK_PUB_FILE "alice_ik_pub"
#define ALICE_SK_PREFIX "sk_with_" // e.g., "sk_with_bob"

#define URL_BUFFER_SIZE 256
#define SHARED_KEY_SIZE 32
#define KDF_INPUT_MAX_SIZE 160

/**
 * @brief Get the NVS key for the shared key file.
 * @param path_buf Buffer to store the NVS key.
 * @param buf_len Length of the buffer.
 * @param recipient The recipient's username.
 */
void get_sk_path(char *path_buf, size_t buf_len, const char *recipient) {
    snprintf(path_buf, buf_len, "%s%s", ALICE_SK_PREFIX, recipient);
}


// --- 1. Alice Register ---
int alice_register() {
    ESP_LOGI(TAG, "--- Alice: Registering ---");

    if (nvs_key_exists(ALICE_IK_PRIV_FILE)) {
        ESP_LOGW(TAG, "WARNING: Keys already exist.");
        short int c, extra;
        while(1){
            printf("Are you sure you want to overwrite them? (y/n): ");
            fflush(stdout); 
            
            c = -1; // Reset c

            // Get the first valid character
            while(1) {
                c = fgetc(stdin);
                if (c < 0) { // No input
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
    char *ik_pub_b64 = NULL;
    cJSON *upload_data = NULL;
    ResponseInfo resp = {0};
    short int ret = -1;

    // 1. Generate Identity Key (IK)
    randombytes_buf(ik_priv, sizeof(ik_priv));
    priv_to_curve25519_pub(ik_pub, ik_priv);

    // 2. Save keys locally to NVS
    if (nvs_write_blob_str(ALICE_IK_PRIV_FILE, ik_priv, sizeof(ik_priv)) != 0 ||
        nvs_write_blob_str(ALICE_IK_PUB_FILE, ik_pub, sizeof(ik_pub)) != 0) {
        ESP_LOGE(TAG, "Failed to write Alice's local keys to NVS.");
        goto cleanup;
    }

    // 3. Create JSON to upload
    ik_pub_b64 = b64_encode(ik_pub, sizeof(ik_pub));
    if (!ik_pub_b64) goto cleanup;
    
    upload_data = cJSON_CreateObject();
    cJSON_AddStringToObject(upload_data, "username", ALICE_USERNAME);
    cJSON_AddStringToObject(upload_data, "ik_b64", ik_pub_b64);
    
    // 4. "Upload" to server
    if (http_post_json(SERVER_URL "/register_ik", upload_data, &resp) != 0 || (resp.http_code != 201)) {
        ESP_LOGE(TAG, "Failed to register IK with server. Code: %ld", resp.http_code);
        ESP_LOGE(TAG, "Server response: %s", resp.body ? resp.body : "N/A");
        goto cleanup;
    }

    ESP_LOGI(TAG, "Alice registered IK successfully.");
    ret = 0;

cleanup:
    sodium_memzero(ik_priv, sizeof(ik_priv));
    free(ik_pub_b64);
    if (upload_data) cJSON_Delete(upload_data);
    cleanup_response(&resp);
    return ret;
}

// --- 2. Alice Send Initial X3DH Message ---
int alice_send_initial_message(const char *recipient) {
    ESP_LOGI(TAG, "--- Alice: Initializing session with %s ---", recipient);

    unsigned char ik_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char ik_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char ek_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char ek_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char bob_ik_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char bob_spk_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char bob_opk_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char signature[crypto_sign_ed25519_BYTES];
    
    unsigned char kdf_input[KDF_INPUT_MAX_SIZE];
    size_t kdf_input_len = 0;
    
    char *ad_b64 = NULL;
    char *ik_pub_b64 = NULL;
    char *ek_pub_b64 = NULL;
    char *ciphertext_b64 = NULL;
    char *nonce_b64 = NULL;
    char *message_text = NULL;
    unsigned char *ciphertext = NULL;

    cJSON *bundle = NULL;
    cJSON *msg_data = NULL;
    
    ResponseInfo get_resp = {0};
    ResponseInfo post_resp = {0};
    short int ret = -1;
    short int opk_id = -1;
    short int has_opk = 0;

    // 1. Load Alice's identity keys from NVS
    if (nvs_read_blob_str(ALICE_IK_PRIV_FILE, ik_priv, sizeof(ik_priv)) != 0 ||
        nvs_read_blob_str(ALICE_IK_PUB_FILE, ik_pub, sizeof(ik_pub)) != 0) {
        ESP_LOGE(TAG, "Failed to read Alice's local keys from NVS. Have you registered?");
        goto cleanup;
    }

    // 2. Generate Ephemeral Key (EK)
    randombytes_buf(ek_priv, sizeof(ek_priv));
    priv_to_curve25519_pub(ek_pub, ek_priv);

    // 3. Fetch recipient's bundle from server
    char url_buf[URL_BUFFER_SIZE];
    snprintf(url_buf, sizeof(url_buf), SERVER_URL "/get_bundle/%s", recipient);
    ESP_LOGI(TAG, "Fetching key bundle for %s...", recipient);

    if (http_get(url_buf, &get_resp) != 0 || get_resp.http_code != 200) {
        ESP_LOGE(TAG, "Failed to get bundle for %s. Code: %ld", recipient, get_resp.http_code);
        ESP_LOGE(TAG, "Server response: %s", get_resp.body ? get_resp.body : "N/A");
        goto cleanup;
    }
    ESP_LOGI(TAG, "Key bundle fetched.");

    // 4. Parse the bundle
    bundle = cJSON_Parse(get_resp.body);
    if (!bundle) {
        ESP_LOGE(TAG, "Failed to parse server bundle JSON");
        goto cleanup;
    }
    
    const cJSON *j_bob_ik_b64 = cJSON_GetObjectItemCaseSensitive(bundle, "ik_b64");
    const cJSON *j_bob_spk_b64 = cJSON_GetObjectItemCaseSensitive(bundle, "spk_b64");
    const cJSON *j_bob_sig_b64 = cJSON_GetObjectItemCaseSensitive(bundle, "spk_sig_b64");
    const cJSON *j_bob_opk_b64 = cJSON_GetObjectItemCaseSensitive(bundle, "opk_b64");
    const cJSON *j_opk_id = cJSON_GetObjectItemCaseSensitive(bundle, "opk_id");
    
    if (!cJSON_IsString(j_bob_ik_b64) || !cJSON_IsString(j_bob_spk_b64) || !cJSON_IsString(j_bob_sig_b64)) {
        ESP_LOGE(TAG, "Failed to unpack bundle JSON (missing keys)");
        goto cleanup;
    }

    const char *bob_ik_b64 = j_bob_ik_b64->valuestring;
    const char *bob_spk_b64 = j_bob_spk_b64->valuestring;
    const char *bob_sig_b64 = j_bob_sig_b64->valuestring;
    const char *bob_opk_b64 = NULL;
    
    if (cJSON_IsString(j_bob_opk_b64) && cJSON_IsNumber(j_opk_id)) {
        bob_opk_b64 = j_bob_opk_b64->valuestring;
        opk_id = j_opk_id->valueint;
        has_opk = 1;
    }

    unsigned char *decoded_ik = NULL;
    unsigned char *decoded_spk = NULL;
    unsigned char *decoded_sig = NULL;
    size_t ik_len, spk_len, sig_len;

    decoded_ik = b64_decode_ex(bob_ik_b64, 0, &ik_len);
    decoded_spk = b64_decode_ex(bob_spk_b64, 0, &spk_len);
    decoded_sig = b64_decode_ex(bob_sig_b64, 0, &sig_len);

    if (!decoded_ik || !decoded_spk || !decoded_sig) {
        ESP_LOGE(TAG, "Failed to b64-decode one or more keys.");
        goto cleanup_b64;
    }

    if (ik_len != sizeof(bob_ik_pub) || spk_len != sizeof(bob_spk_pub) || sig_len != sizeof(signature)) {
        ESP_LOGE(TAG, "Decoded key length mismatch.");
        goto cleanup_b64;
    }

    // Copy decoded data into stack buffers
    memcpy(bob_ik_pub, decoded_ik, ik_len);
    memcpy(bob_spk_pub, decoded_spk, spk_len);
    memcpy(signature, decoded_sig, sig_len);

    // Free the temp buffers
    free(decoded_ik);
    free(decoded_spk);
    free(decoded_sig);
    decoded_ik = decoded_spk = decoded_sig = NULL;
    
    if (has_opk) {
        if (b64_decode(bob_opk_b64, bob_opk_pub, sizeof(bob_opk_pub)) != sizeof(bob_opk_pub)) {
            ESP_LOGE(TAG, "Failed to decode OPK from bundle.");
            goto cleanup;
        }
    }

    // 5. Verify SPK signature
    unsigned char ed_bob_ik_pub[crypto_sign_ed25519_PUBLICKEYBYTES];
    curve25519_pub_to_ed25519_pub(ed_bob_ik_pub, bob_ik_pub, 0);

    if (ed25519_verify(signature, ed_bob_ik_pub, bob_spk_pub, sizeof(bob_spk_pub)) != 0) {
        ESP_LOGE(TAG, "Invalid SPK signature! Aborting.");
        goto cleanup;
    }
    ESP_LOGI(TAG, "SPK signature verified successfully.");
    if (has_opk) {
        ESP_LOGI(TAG, "Using One-Time Prekey (OPK) id: %d", opk_id);
    } else {
        ESP_LOGI(TAG, "No OPK available. Proceeding without one.");
    }

    // 6. Perform DH calculations
    unsigned char dh1[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh2[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh3[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh4[crypto_scalarmult_curve25519_BYTES];

    if (x25519(dh1, ik_priv, bob_spk_pub) != 0 ||
        x25519(dh2, ek_priv, bob_ik_pub) != 0 ||
        x25519(dh3, ek_priv, bob_spk_pub) != 0) {
        ESP_LOGE(TAG, "DH calculation failed.");
        goto cleanup;
    }
    
    if (has_opk) {
        if (x25519(dh4, ek_priv, bob_opk_pub) != 0) {
            ESP_LOGE(TAG, "DH4 calculation failed.");
            goto cleanup;
        }
    }

    // 7. Concatenate DH outputs
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

    // 8. Derive Shared Key (SK)
    unsigned char sk[SHARED_KEY_SIZE];
    if (hkdf(sk, sizeof(sk), kdf_input, kdf_input_len, X3DH_INFO_STRING) != 0) {
        ESP_LOGE(TAG, "KDF failed.");
        goto cleanup;
    }

    ESP_LOGI(TAG, "Shared Key (SK) computed successfully (Alice).");

    // Save SK to NVS
    char sk_path[64];
    get_sk_path(sk_path, sizeof(sk_path), recipient);
    if (nvs_write_blob_str(sk_path, sk, sizeof(sk)) != 0) {
        ESP_LOGE(TAG, "Failed to save shared key to NVS key %s!", sk_path);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Shared key saved to NVS key: %s", sk_path);

    // 9. Calculate Associated Data (AD)
    unsigned char ad[crypto_scalarmult_curve25519_BYTES * 2];
    memcpy(ad, ik_pub, sizeof(ik_pub));
    memcpy(ad + sizeof(ik_pub), bob_ik_pub, sizeof(bob_ik_pub));
    ad_b64 = b64_encode(ad, sizeof(ad));

    // 10. Get message, encrypt, and package
    printf("Enter message: ");
    fflush(stdout);
    message_text = read_message_from_stdin();
    if (!message_text || strlen(message_text) == 0) {
        ESP_LOGE(TAG, "No message entered. Aborting.");
        goto cleanup;
    }
    
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned long long ciphertext_len = strlen(message_text) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        ESP_LOGE(TAG, "Failed to malloc for ciphertext");
        goto cleanup;
    }

    crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
        (const unsigned char *)message_text, strlen(message_text),
        ad, sizeof(ad), // Associated Data
        NULL, nonce, sk);
    
    // 11. B64-encode everything for JSON
    ik_pub_b64 = b64_encode(ik_pub, sizeof(ik_pub));
    ek_pub_b64 = b64_encode(ek_pub, sizeof(ek_pub));
    ciphertext_b64 = b64_encode(ciphertext, ciphertext_len);
    nonce_b64 = b64_encode(nonce, sizeof(nonce));

    if (!ik_pub_b64 || !ek_pub_b64 || !ciphertext_b64 || !ad_b64 || !nonce_b64) {
        ESP_LOGE(TAG, "Failed to b64-encode keys/ciphertext for JSON");
        goto cleanup;
    }

    // 12. Send initial message to Bob
    msg_data = cJSON_CreateObject();
    cJSON_AddStringToObject(msg_data, "from", ALICE_USERNAME);
    cJSON_AddStringToObject(msg_data, "to", recipient);
    cJSON_AddStringToObject(msg_data, "ik_b64", ik_pub_b64);
    cJSON_AddStringToObject(msg_data, "ek_b64", ek_pub_b64);
    cJSON_AddNumberToObject(msg_data, "opk_id", opk_id);
    cJSON_AddStringToObject(msg_data, "ciphertext_b64", ciphertext_b64);
    cJSON_AddStringToObject(msg_data, "ad_b64", ad_b64);
    cJSON_AddStringToObject(msg_data, "nonce_b64", nonce_b64);

    if (http_post_json(SERVER_URL "/send_initial_message", msg_data, &post_resp) != 0 || post_resp.http_code != 201) {
        ESP_LOGE(TAG, "Failed to send initial message to server. Code: %ld", post_resp.http_code);
        ESP_LOGE(TAG, "Server response: %s", post_resp.body ? post_resp.body : "N/A");
        goto cleanup;
    }

    ESP_LOGI(TAG, "Initial message sent to server for %s.", recipient);
    ret = 0;

cleanup_b64:
    if (decoded_ik) free(decoded_ik);
    if (decoded_spk) free(decoded_spk);
    if (decoded_sig) free(decoded_sig);
    sodium_memzero(sk, sizeof(sk));
    return -1;

cleanup:
    sodium_memzero(ek_priv, sizeof(ek_priv));
    sodium_memzero(dh1, sizeof(dh1));
    sodium_memzero(dh2, sizeof(dh2));
    sodium_memzero(dh3, sizeof(dh3));
    sodium_memzero(dh4, sizeof(dh4));
    sodium_memzero(kdf_input, sizeof(kdf_input));
    sodium_memzero(sk, sizeof(sk));
    free(ad_b64);
    free(ik_pub_b64);
    free(ek_pub_b64);
    free(ciphertext_b64);
    free(nonce_b64);
    free(message_text);
    free(ciphertext);
    if (bundle) cJSON_Delete(bundle);
    if (msg_data) cJSON_Delete(msg_data);
    cleanup_response(&get_resp);
    cleanup_response(&post_resp);
    return ret;
}

// --- 3. Alice Send Chat Message (Post-X3DH) ---
int alice_send_chat_message(const char *recipient) {
    // 1. Load the shared key
    unsigned char sk[SHARED_KEY_SIZE];
    char sk_path[64];
    get_sk_path(sk_path, sizeof(sk_path), recipient);

    if (nvs_read_blob_str(sk_path, sk, sizeof(sk)) != 0) {
        ESP_LOGE(TAG, "No shared key found for %s. Run 'init_message %s' first.", recipient, recipient);
        return -1;
    }
    
    // 2. Get message from stdin
    printf("Enter message: ");
    fflush(stdout);
    char *message_text = read_message_from_stdin();
    if (!message_text || strlen(message_text) == 0) {
        ESP_LOGW(TAG, "No message entered...");
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
    
    // 5. Pack JSON (cJSON) and send
    cJSON *msg_data = cJSON_CreateObject();
    cJSON_AddStringToObject(msg_data, "from", ALICE_USERNAME);
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

// --- 4. Alice Read Chat Messages (Post-X3DH) ---
int alice_read_chat_messages(const char *sender) {
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
    snprintf(url_buf, URL_BUFFER_SIZE, SERVER_URL "/get_chat_messages/%s/from/%s", ALICE_USERNAME, sender);
    
    ResponseInfo resp = {0};
    if (http_get(url_buf, &resp) != 0 || resp.http_code != 200) {
        ESP_LOGE(TAG, "Failed to get chat messages. Code: %ld", resp.http_code);
        ESP_LOGE(TAG, "Server response: %s", resp.body ? resp.body : "N/A");
        sodium_memzero(sk, sizeof(sk));
        cleanup_response(&resp);
        return -1;
    }
    
    // 3. Parse the message list (cJSON array)
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