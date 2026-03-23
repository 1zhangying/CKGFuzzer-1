#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests the following APIs:
// - cJSON_Parse: Parse JSON string to cJSON object
// - cJSON_Print: Convert cJSON object back to JSON string
// - cJSON_CreateString: Create a cJSON string object
// - cJSON_GetStringValue: Extract string value from cJSON object
// - cJSON_AddStringToObject: Add a string property to a JSON object

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated string from input data
    char* input_str = (char*)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Test cJSON_Parse - parse the input string into a cJSON object
    cJSON* parsed_json = cJSON_Parse(input_str);
    
    // Test cJSON_Print regardless of parse result
    char* printed_str = NULL;
    if (parsed_json != NULL) {
        printed_str = cJSON_Print(parsed_json);
        
        // Test cJSON_GetStringValue if the parsed object is a string
        if (cJSON_IsString(parsed_json)) {
            const char* str_value = cJSON_GetStringValue(parsed_json);
            // Just check the return value - could be NULL if not a string
        }
    }

    // Create a new JSON object to test adding string properties
    cJSON* root_obj = cJSON_CreateObject();
    if (root_obj != NULL) {
        // Create a sample string object
        cJSON* string_obj = cJSON_CreateString("sample_value");
        if (string_obj != NULL) {
            // Add the string object to the root object
            cJSON_AddItemToObject(root_obj, "sample_key", string_obj);
            
            // Test adding another string using cJSON_AddStringToObject
            cJSON_AddStringToObject(root_obj, "added_string", "test_string_value");
            
            // Try to get string value from the added string
            cJSON* added_string = cJSON_GetObjectItem(root_obj, "added_string");
            if (added_string != NULL && cJSON_IsString(added_string)) {
                const char* retrieved_str = cJSON_GetStringValue(added_string);
                // Just verify we can call the function
            }
            
            // Print the modified object
            char* modified_printed = cJSON_Print(root_obj);
            if (modified_printed != NULL) {
                free(modified_printed);
            }
        }
        
        // Clean up the root object
        cJSON_Delete(root_obj);
    }

    // Clean up parsed JSON if it was successfully created
    if (parsed_json != NULL) {
        cJSON_Delete(parsed_json);
    }

    // Clean up printed string if it was successfully created
    if (printed_str != NULL) {
        free(printed_str);
    }

    // Free the input string
    free(input_str);

    return 0;
}
