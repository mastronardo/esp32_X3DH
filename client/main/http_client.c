#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "esp_http_client.h"
#include "http_client.h"
#include <cJSON.h>

static const char *TAG = "http_client";

/**
 * @brief Initialize a ResponseInfo struct.
 * @param resp Pointer to ResponseInfo struct to initialize.
 */
static void init_response(ResponseInfo *resp) {
    resp->size = 0;
    resp->body = malloc(1); // Start with 1 byte
    if (resp->body) {
        resp->body[0] = '\0';
    }
    resp->http_code = 0;
}

/**
 * @brief Free the memory allocated for the response body.
 * @param resp Pointer to ResponseInfo struct to clean up.
 */
void cleanup_response(ResponseInfo *resp) {
    if (resp->body) {
        free(resp->body);
        resp->body = NULL;
    }
    resp->size = 0;
}

/**
 * @brief Event handler for esp_http_client.
 * @param evt Pointer to esp_http_client_event_t structure.
 * @return esp_err_t ESP_OK on success, ESP_FAIL on failure.
 */
static esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    ResponseInfo *resp_info = (ResponseInfo *)evt->user_data;

    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGE(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            if (resp_info) {
                // Reallocate buffer
                char *ptr = realloc(resp_info->body, resp_info->size + evt->data_len + 1);
                if (ptr == NULL) {
                    ESP_LOGE(TAG, "Failed to realloc memory for HTTP response");
                    return ESP_FAIL;
                }
                resp_info->body = ptr;
                // Copy new data
                memcpy(resp_info->body + resp_info->size, evt->data, evt->data_len);
                resp_info->size += evt->data_len;
                resp_info->body[resp_info->size] = '\0'; // Null-terminate
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
            break;
    }
    return ESP_OK;
}

/**
 * @brief Perform an HTTP GET request.
 * @param url The URL to send the GET request to.
 * @param resp_info Pointer to ResponseInfo struct to store the response.
 * @return int 0 on success, -1 on failure.
 * @note Caller is responsible for freeing the response info.
 */
int http_get(const char *url, ResponseInfo *resp_info) {
    init_response(resp_info);

    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handler,
        .user_data = resp_info,
        .disable_auto_redirect = false,
        .timeout_ms = 15000,
    };
    
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        return -1;
    }
    esp_http_client_set_header(client, "Cache-Control", "no-cache");

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return -1;
    }

    resp_info->http_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    
    ESP_LOGD(TAG, "GET request to %s finished with code %ld, body size %zu", url, resp_info->http_code, resp_info->size);

    return 0;
}


/**
 * @brief Perform an HTTP POST request with a cJSON payload.
 * @param url The URL to send the POST request to.
 * @param payload The cJSON object to send as the POST body.
 * @param resp_info Pointer to ResponseInfo struct to store the response.
 * @return int 0 on success, -1 on failure.
 * @note Caller is responsible for freeing the cJSON payload and the response info.
 */
int http_post_json(const char *url, cJSON *payload, ResponseInfo *resp_info) {
    init_response(resp_info);

    // Serialize cJSON payload
    char *payload_str = cJSON_PrintUnformatted(payload);
    if (!payload_str) {
        ESP_LOGE(TAG, "Failed to print cJSON payload");
        return -1;
    }

    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handler,
        .user_data = resp_info,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 15000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        cJSON_free(payload_str);
        return -1;
    }

    // Set headers and post data
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, payload_str, strlen(payload_str));

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
        cJSON_free(payload_str);
        esp_http_client_cleanup(client);
        return -1;
    }

    resp_info->http_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    cJSON_free(payload_str);

    ESP_LOGD(TAG, "POST request to %s finished with code %ld, body size %zu", url, resp_info->http_code, resp_info->size);
    return 0;
}