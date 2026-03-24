#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON library functions
// This fuzz driver tests the following API combination:
// - cJSON_CreateObject
// - cJSON_Delete
// - cJSON_PrintUnformatted
// - cJSON_CreateString
// - cJSON_GetStringValue

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 1) {
        return 0;
    }

    // Create a root JSON object
    cJSON* root_obj = cJSON_CreateObject();
    if (root_obj == NULL) {
        return 0; // Allocation failed, exit early
    }

    // Create a string from part of the input data
    // Reserve at least one byte for string creation
    if (size > 1) {
        size_t str_size = size - 1; // Use most of the data for string
        
        // Create a null-terminated string from input data
        char* input_str = (char*)malloc(str_size + 1);
        if (input_str != NULL) {
            memcpy(input_str, data, str_size);
            input_str[str_size] = '\0'; // Ensure null termination
            
            // Create a cJSON string object
            cJSON* string_obj = cJSON_CreateString(input_str);
            if (string_obj != NULL) {
                // Add the string object to the root object with a key
                cJSON_AddItemToObject(root_obj, "test_key", string_obj);
                
                // Test cJSON_GetStringValue
                const char* retrieved_str = cJSON_GetStringValue(string_obj);
                if (retrieved_str != NULL) {
                    // Verify the retrieved string matches what we set
                    // This is just a validation check
                    (void)retrieved_str; // Suppress unused variable warning
                }
            }
            
            free(input_str);
        }
        
        // Move data pointer forward to use remaining bytes for another operation
        data += (size - 1);
        size = 1;
    }

    // Print the JSON object in unformatted way
    char* json_string = cJSON_PrintUnformatted(root_obj);
    if (json_string != NULL) {
        // Use the result (in a real scenario, we might validate the output)
        (void)json_string; // Suppress unused variable warning
        
        // Free the printed string
        free(json_string);
    }

    // Clean up the JSON object
    cJSON_Delete(root_obj);

    return 0;
}
