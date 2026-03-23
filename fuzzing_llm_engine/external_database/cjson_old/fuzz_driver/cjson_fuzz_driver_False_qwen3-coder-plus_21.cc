#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests the following APIs:
// - cJSON_ParseWithLength: Parse JSON from buffer with length
// - cJSON_Print: Convert JSON object back to string
// - cJSON_Delete: Free JSON object memory
// - cJSON_CreateString: Create a string JSON object
// - cJSON_CreateObject: Create an empty JSON object
// - cJSON_AddStringToObject: Add a string property to an object

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure minimum size for basic operations
    if (size < 1) {
        return 0;
    }

    // Create a copy of input data to avoid modifying original
    char* input_copy = nullptr;
    if (size > 0) {
        input_copy = (char*)malloc(size + 1);  // +1 for null terminator
        if (!input_copy) {
            return 0;  // Allocation failed
        }
        memcpy(input_copy, data, size);
        input_copy[size] = '\0';  // Null terminate for string operations
    }

    // Test 1: Parse input as JSON
    cJSON* parsed_json = cJSON_ParseWithLength(input_copy, size);
    
    // If parsing succeeded, test print functionality
    if (parsed_json != nullptr) {
        char* printed_json = cJSON_Print(parsed_json);
        if (printed_json != nullptr) {
            // Successfully printed the JSON
            free(printed_json);  // Free the printed string
        }
        
        // Clean up the parsed JSON object
        cJSON_Delete(parsed_json);
    }

    // Test 2: Create a new JSON object programmatically
    cJSON* obj = cJSON_CreateObject();
    if (obj != nullptr) {
        // Try to add a string to the object
        // Use part of the input data as the string value
        if (size > 10) {  // Need enough data for both key and value
            // Create a null-terminated key string from first few bytes
            size_t key_len = size > 20 ? 10 : size / 2;
            char* key_str = (char*)malloc(key_len + 1);
            if (key_str) {
                memcpy(key_str, input_copy, key_len);
                key_str[key_len] = '\0';
                
                // Create a value string from remaining bytes
                size_t val_start = key_len;
                size_t val_len = size - val_start;
                char* val_str = (char*)malloc(val_len + 1);
                if (val_str) {
                    memcpy(val_str, input_copy + val_start, val_len);
                    val_str[val_len] = '\0';
                    
                    // Add string to object
                    cJSON* added_string = cJSON_AddStringToObject(obj, key_str, val_str);
                    if (added_string != nullptr) {
                        // Successfully added string to object
                        // Print the object to verify
                        char* printed_obj = cJSON_Print(obj);
                        if (printed_obj != nullptr) {
                            free(printed_obj);
                        }
                    }
                    
                    free(val_str);
                }
                
                free(key_str);
            }
        } else {
            // Add a simple hardcoded string if not enough data
            cJSON* added_string = cJSON_AddStringToObject(obj, "test_key", "test_value");
            if (added_string != nullptr) {
                // Successfully added string to object
                char* printed_obj = cJSON_Print(obj);
                if (printed_obj != nullptr) {
                    free(printed_obj);
                }
            }
        }
        
        // Clean up the created object
        cJSON_Delete(obj);
    }

    // Test 3: Create a string JSON object directly
    if (size > 0) {
        // Use part of the input as string content
        size_t str_len = size > 100 ? 100 : size;  // Limit string length to prevent excessive memory usage
        char* temp_str = (char*)malloc(str_len + 1);
        if (temp_str) {
            memcpy(temp_str, input_copy, str_len);
            temp_str[str_len] = '\0';
            
            cJSON* string_obj = cJSON_CreateString(temp_str);
            if (string_obj != nullptr) {
                // Successfully created string object
                char* printed_string = cJSON_Print(string_obj);
                if (printed_string != nullptr) {
                    free(printed_string);
                }
                
                cJSON_Delete(string_obj);
            }
            
            free(temp_str);
        }
    }

    // Clean up the input copy
    if (input_copy) {
        free(input_copy);
    }

    return 0;
}
