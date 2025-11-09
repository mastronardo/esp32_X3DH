#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "sodium.h"
#include <xeddsa.h>
#include "common.h"

// Bring in Alice and Bob's function prototypes
int alice_register();
int alice_send_initial_message(const char *recipient);
int alice_send_chat_message(const char *recipient);
int alice_read_chat_messages(const char *sender);
int bob_register();
int bob_read_initial_message();
int bob_send_chat_message(const char *recipient);
int bob_read_chat_messages(const char *sender);

static const char *TAG = "app_main";

// --- WiFi Connection ---
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
static int s_retry_num = 0;

static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < 5) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "<YOUR_SSID>",
            .password = "<YOUR_PASSWORD>",
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to ap");
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "Failed to connect to ap");
    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }
}


#if CONFIG_ACTOR_IS_ALICE
void run_alice_menu() {
    char *cmd_buf = NULL;
    while(1) {
        ESP_LOGI(TAG, "\n=========================\n"
                      " ESP32 X3DH Client (Alice)\n"
                      "=========================\n"
                      "(r) Register\n"
                      "(i) Send Initial Message to Bob\n"
                      "(s) Send Chat Message to Bob\n"
                      "(l) Listen for Chat Messages from Bob\n"
                      "=========================\n"
                      "Enter command:");
        
        cmd_buf = read_message_from_stdin();
        if (!cmd_buf) continue; // Handle allocation failure
        
        if (strlen(cmd_buf) == 0) {
            free(cmd_buf);
            continue;
        }

        char cmd = cmd_buf[0];
        switch(cmd) {
            case 'r':
                ESP_LOGI(TAG, "Executing: Register");
                alice_register();
                break;
            case 'i':
                ESP_LOGI(TAG, "Executing: Send Initial Message to bob");
                alice_send_initial_message("bob");
                break;
            case 's':
                ESP_LOGI(TAG, "Executing: Send Chat Message to bob");
                alice_send_chat_message("bob");
                break;
            case 'l':
                ESP_LOGI(TAG, "Executing: Read Chat Messages from bob");
                alice_read_chat_messages("bob");
                break;
            default:
                ESP_LOGW(TAG, "Unknown command: %c", cmd);
                break;
        }
        vTaskDelay(pdMS_TO_TICKS(1000)); // Short delay
        free(cmd_buf);
    }
}

#elif CONFIG_ACTOR_IS_BOB
void run_bob_menu() {
    char *cmd_buf = NULL;
    while(1) {
        ESP_LOGI(TAG, "\n=========================\n"
                      " ESP32 X3DH Client (Bob)\n"
                      "=========================\n"
                      "(r) Register\n"
                      "(i) Read Initial Message from Alice\n"
                      "(s) Send Chat Message to Alice\n"
                      "(l) Listen for Chat Messages from Alice\n"
                      "=========================\n"
                      "Enter command:");

        cmd_buf = read_message_from_stdin();
        if (!cmd_buf) continue; // Handle allocation failure

        if (strlen(cmd_buf) == 0) {
            free(cmd_buf);
            continue;
        }

        char cmd = cmd_buf[0];
        switch(cmd) {
            case 'r':
                ESP_LOGI(TAG, "Executing: Register");
                bob_register();
                break;
            case 'i':
                ESP_LOGI(TAG, "Executing: Read Initial Message from alice");
                bob_read_initial_message();
                break;
            case 's':
                ESP_LOGI(TAG, "Executing: Send Chat Message to alice");
                bob_send_chat_message("alice");
                break;
            case 'l':
                ESP_LOGI(TAG, "Executing: Read Chat Messages from alice");
                bob_read_chat_messages("alice");
                break;
            default:
                ESP_LOGW(TAG, "Unknown command: %c", cmd);
                break;
        }
        vTaskDelay(pdMS_TO_TICKS(1000)); // Short delay
        free(cmd_buf);
    }
}
#endif


void app_main(void)
{
    // 1. Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_LOGI(TAG, "NVS Initialized.");

    // 2. Initialize WiFi
    ESP_LOGI(TAG, "Initializing WiFi...");
    wifi_init_sta();
    ESP_LOGI(TAG, "WiFi Connected.");

    // 3. Initialize Crypto Libraries
    if (sodium_init() == -1) {
        ESP_LOGE(TAG, "Failed to initialize libsodium!");
        return;
    }
    if (xeddsa_init() < 0) {
        ESP_LOGE(TAG, "Failed to initialize libxeddsa!");
        return;
    }
    ESP_LOGI(TAG, "Crypto Libraries Initialized.");

    // 4. Run the correct actor's menu based on Kconfig
    #if CONFIG_ACTOR_IS_ALICE
    ESP_LOGI(TAG, "Starting Alice's task...");
    xTaskCreate(run_alice_menu, "alice_menu_task", 8192, NULL, 5, NULL); // <-- ADD THIS
    #elif CONFIG_ACTOR_IS_BOB
    ESP_LOGI(TAG, "Starting Bob's task...");
    xTaskCreate(run_bob_menu, "bob_menu_task", 8192, NULL, 5, NULL); // <-- ADD THIS
    #else
    ESP_LOGE(TAG, "No actor selected! Please run 'idf.py menuconfig'.");
    #endif
}