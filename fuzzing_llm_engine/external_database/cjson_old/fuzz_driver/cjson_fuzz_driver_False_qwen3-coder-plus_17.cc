#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests the following APIs:
// - cJSON_CreateObject
// - cJSON_CreateNull
// - cJSON_AddNullToObject
// - cJSON_IsNull
// - cJSON_Print
// - cJSON_Delete

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 4) {
        return 0;
    }

    // Create a root JSON object
    cJSON *root_obj = cJSON_CreateObject();
    if (root_obj == NULL) {
        return 0;  // Failed to create object, exit early
    }

    // Create a null JSON value
    cJSON *null_val = cJSON_CreateNull();
    if (null_val == NULL) {
        cJSON_Delete(root_obj);  // Clean up before returning
        return 0;
    }

    // Test cJSON_IsNull on the created null value
    if (!cJSON_IsNull(null_val)) {
        // This should not happen if cJSON_CreateNull works correctly
        cJSON_Delete(null_val);
        cJSON_Delete(root_obj);
        return 0;
    }

    // Try to add the null value to the root object with a static key
    // Only proceed if we have enough data for a simple operation
    if (size >= 5) {
        cJSON *added_null = cJSON_AddNullToObject(root_obj, "test_key");
        if (added_null != NULL) {
            // Verify that the added value is indeed null
            if (!cJSON_IsNull(added_null)) {
                // Unexpected state
            }
        } else {
            // Failed to add null to object, but continue with what we have
        }
    }

    // Create another object and try to add null with dynamic key
    // Extract a portion of the input data to use as a key name
    if (size > 10) {
        size_t key_len = size - 10;
        if (key_len > 20) key_len = 20;  // Limit key length to prevent excessive memory usage
        
        char *key_name = (char*)malloc(key_len + 1);
        if (key_name != NULL) {
            memcpy(key_name, data + 10, key_len);
            
            // Ensure it's null-terminated
            key_name[key_len] = '\0';
            
            // Replace non-printable characters with underscores to make valid JSON keys
            for (size_t i = 0; i < key_len; i++) {
                if (key_name[i] < 32 || key_name[i] > 126) {
                    key_name[i] = '_';
                }
            }
            
            cJSON *added_with_dynamic_key = cJSON_AddNullToObject(root_obj, key_name);
            if (added_with_dynamic_key != NULL) {
                // Verify that the added value is null
                if (!cJSON_IsNull(added_with_dynamic_key)) {
                    // Unexpected state
                }
            }
            
            free(key_name);
        }
    }

    // Test cJSON_Print to serialize the JSON object
    char *json_string = cJSON_Print(root_obj);
    if (json_string != NULL) {
        // Successfully printed, now free the string
        free(json_string);
    }

    // Perform additional checks based on the input data
    // Use first few bytes to decide which additional operations to perform
    if (size > 4) {
        uint32_t control_value = *(uint32_t*)data;
        
        // Based on the control value, perform different operations
        switch (control_value % 4) {
            case 0: {
                // Add multiple nulls to the object
                for (int i = 0; i < 3 && (i * 4 + 4) < size; i++) {
                    char key[20];
                    snprintf(key, sizeof(key), "key_%d", i);
                    cJSON_AddNullToObject(root_obj, key);
                }
                break;
            }
            case 1: {
                // Create another object and add our null to it
                cJSON *second_obj = cJSON_CreateObject();
                if (second_obj != NULL) {
                    cJSON_AddNullToObject(second_obj, "nested_null");
                    
                    // Print the second object too
                    char *second_json_str = cJSON_Print(second_obj);
                    if (second_json_str != NULL) {
                        free(second_json_str);
                    }
                    
                    cJSON_Delete(second_obj);
                }
                break;
            }
            case 2: {
                // Test creating multiple nulls and checking them
                cJSON *null1 = cJSON_CreateNull();
                cJSON *null2 = cJSON_CreateNull();
                
                if (null1 != NULL && null2 != NULL) {
                    if (cJSON_IsNull(null1) && cJSON_IsNull(null2)) {
                        // Both are null as expected
                    }
                    
                    // Don't delete these yet, they'll be cleaned up later
                } else {
                    if (null1 != NULL) cJSON_Delete(null1);
                    if (null2 != NULL) cJSON_Delete(null2);
                }
                break;
            }
            case 3: {
                // Do nothing extra, just continue
                break;
            }
        }
    }

    // Final cleanup - delete the entire JSON structure
    cJSON_Delete(root_obj);

    return 0;
}
