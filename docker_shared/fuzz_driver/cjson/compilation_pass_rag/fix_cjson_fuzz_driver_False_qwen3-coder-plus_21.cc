#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests the following APIs:
// - cJSON_Parse: Parse JSON string into cJSON structure
// - cJSON_CreateString: Create a cJSON string object
// - cJSON_AddItemToObject: Add items to JSON object
// - cJSON_Duplicate: Deep copy of JSON structure
// - cJSON_PrintUnformatted: Serialize JSON to unformatted string

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char* json_string = (char*)malloc(size + 1);
    if (!json_string) {
        return 0;
    }
    
    memcpy(json_string, data, size);
    json_string[size] = '\0';

    // Parse the input string as JSON
    cJSON* parsed_json = cJSON_Parse(json_string);
    
    // Test cJSON_CreateString first with a portion of the input
    char* test_string = nullptr;
    cJSON* string_item = nullptr;
    if (size > 0) {
        // Create a null-terminated substring from input for testing
        size_t str_len = size > 10 ? 10 : size;  // Limit length for string creation
        test_string = (char*)malloc(str_len + 1);
        if (test_string) {
            memcpy(test_string, data, str_len);
            test_string[str_len] = '\0';
            
            string_item = cJSON_CreateString(test_string);
        }
    }

    // If parsing was successful, perform additional operations
    if (parsed_json) {
        // Test cJSON_Duplicate to create a deep copy
        cJSON* duplicated_json = cJSON_Duplicate(parsed_json, 1); // 1 for recursive duplication
        
        // Test cJSON_PrintUnformatted on the original
        char* unformatted_str = cJSON_PrintUnformatted(parsed_json);
        if (unformatted_str) {
            free(unformatted_str);  // Free the printed string
        }
        
        // If we have a duplicated JSON and a string item, try adding to an object
        if (duplicated_json && string_item) {
            // Create a temporary object to test adding items
            cJSON* temp_obj = cJSON_CreateObject();
            if (temp_obj) {
                // Add the string item to the temporary object
                cJSON_AddItemToObject(temp_obj, "test_key", string_item);
                
                // Also try adding the duplicated JSON as another item
                cJSON_AddItemToObject(temp_obj, "duplicated", duplicated_json);
                
                // Print the combined object
                char* combined_str = cJSON_PrintUnformatted(temp_obj);
                if (combined_str) {
                    free(combined_str);
                }
                
                // Clean up the temporary object (this also cleans up added items)
                cJSON_Delete(temp_obj);
                // Note: We don't delete string_item or duplicated_json here 
                // since they've been added to temp_obj and will be cleaned up with it
            } else {
                // If temp_obj creation failed, clean up manually
                cJSON_Delete(duplicated_json);
                cJSON_Delete(string_item);
            }
        } else {
            // If we couldn't create a temp object, clean up individually
            if (duplicated_json) {
                cJSON_Delete(duplicated_json);
            }
            if (string_item) {
                cJSON_Delete(string_item);
            }
        }
        
        // Clean up the original parsed JSON
        cJSON_Delete(parsed_json);
    } else {
        // If parsing failed but we have a string item, clean it up
        if (string_item) {
            cJSON_Delete(string_item);
        }
    }

    // Clean up allocated memory
    free(json_string);
    if (test_string) {
        free(test_string);
    }

    return 0;
}
