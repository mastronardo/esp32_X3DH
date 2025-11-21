# main/CMakeLists.txt

# List of all source files in the 'main' component
set(SOURCES
    "app_main.c"
    "common.c"
    "http_client.c"
    "alice.c"
    "bob.c"
)

# List of all header include directories
set(INCLUDES
    "."
)

# ESP-IDF macro to register the main component
idf_component_register(
    SRCS "${SOURCES}"
    INCLUDE_DIRS "${INCLUDES}"
    
    # List of components this 'main' component depends on
    REQUIRES
        "libsodium"        # For crypto (from registry)
        "cjson"            # For JSON (from registry)
        "mbedtls"          # For kdf (from IDF) 
        "nvs_flash"        # For storage (from IDF)
        "esp_wifi"         # For networking (from IDF)
        "esp_netif"        # For networking (from IDF)
        "esp_event"        # For events (from IDF)
        "esp_system"       # For system functions (from IDF)
        "esp_http_client"  # For HTTP (from registry)
        "libxeddsa"        # For xeddsa (local component)
)

target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-error=pointer-sign")