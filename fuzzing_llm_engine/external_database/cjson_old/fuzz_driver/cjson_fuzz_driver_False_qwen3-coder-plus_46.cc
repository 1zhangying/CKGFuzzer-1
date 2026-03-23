#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing cJSON library functions
// Tests the following API functions:
// - cJSON_Parse
// - cJSON_IsString
// - cJSON_IsRaw
// - cJSON_GetStringValue
// - cJSON_CreateString
// - cJSON_AddStringToObject

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Limit input size to prevent excessive memory allocation
    if (size > 1024 * 1024) {  // 1MB limit
        return 0;
    }

    // Ensure null-terminated string for JSON parsing
    char* json_str = nullptr;
    cJSON* root = nullptr;
    cJSON* obj = nullptr;

    // Allocate and copy data ensuring null termination
    if (size > 0) {
        json_str = (char*)malloc(size + 1);
        if (!json_str) {
            return 0;
        }
        memcpy(json_str, data, size);
        json_str[size] = '\0';
        
        // Parse the JSON string
        root = cJSON_Parse(json_str);
    } else {
        // If no data, create an empty object to continue testing
        root = cJSON_CreateObject();
    }

    // Test cJSON_Parse result
    if (root != nullptr) {
        // Test cJSON_IsString on the root element
        bool is_string = cJSON_IsString(root);
        
        // Test cJSON_IsRaw on the root element
        bool is_raw = cJSON_IsRaw(root);
        
        // If root is a string, get its value
        if (is_string) {
            char* str_value = cJSON_GetStringValue(root);
            if (str_value != nullptr) {
                // Use the string value in further operations
                cJSON* new_str_item = cJSON_CreateString(str_value);
                if (new_str_item != nullptr) {
                    cJSON_Delete(new_str_item);  // Clean up
                }
            }
        }
        
        // Create a new object to test adding string items
        obj = cJSON_CreateObject();
        if (obj != nullptr) {
            // Try to add a string to the object
            // Use part of the input data as the key and value
            if (size >= 2) {
                size_t key_len = size / 2;
                if (key_len > 0) {
                    char* key = (char*)malloc(key_len + 1);
                    char* value = (char*)malloc((size - key_len) + 1);
                    
                    if (key && value) {
                        memcpy(key, data, key_len);
                        key[key_len] = '\0';
                        
                        memcpy(value, data + key_len, size - key_len);
                        value[size - key_len] = '\0';
                        
                        // Add string to object
                        cJSON* added_item = cJSON_AddStringToObject(obj, key, value);
                        if (added_item != nullptr) {
                            // Verify the added item is a string
                            if (cJSON_IsString(added_item)) {
                                char* retrieved_value = cJSON_GetStringValue(added_item);
                                if (retrieved_value != nullptr) {
                                    // Successfully retrieved string value
                                }
                            }
                        }
                    }
                    
                    if (key) free(key);
                    if (value) free(value);
                }
            }
            
            // Add a hardcoded string as fallback
            cJSON* fallback_item = cJSON_AddStringToObject(obj, "fuzz_key", "fuzz_value");
            if (fallback_item != nullptr) {
                if (cJSON_IsString(fallback_item)) {
                    char* str_val = cJSON_GetStringValue(fallback_item);
                    if (str_val != nullptr) {
                        // Successfully got string value
                    }
                }
            }
            
            cJSON_Delete(obj);  // Clean up object
        }
        
        // Test creating a string directly from input data
        if (size > 0) {
            char* temp_str = (char*)malloc(size + 1);
            if (temp_str) {
                memcpy(temp_str, data, size);
                temp_str[size] = '\0';
                
                cJSON* str_item = cJSON_CreateString(temp_str);
                if (str_item != nullptr) {
                    // Check if created item is a string
                    if (cJSON_IsString(str_item)) {
                        char* value = cJSON_GetStringValue(str_item);
                        if (value != nullptr) {
                            // Successfully retrieved string value
                        }
                    }
                    cJSON_Delete(str_item);
                }
                
                free(temp_str);
            }
        }
        
        cJSON_Delete(root);  // Clean up parsed JSON
    }

    // Clean up allocated memory
    if (json_str) {
        free(json_str);
    }

    return 0;
}
