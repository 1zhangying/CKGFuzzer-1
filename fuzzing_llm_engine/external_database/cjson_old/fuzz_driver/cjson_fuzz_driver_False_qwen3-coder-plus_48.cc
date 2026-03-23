#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests the following APIs:
// - cJSON_Parse
// - cJSON_Print
// - cJSON_Delete
// - cJSON_GetStringValue
// - cJSON_CreateString
// - cJSON_Minify

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be meaningful
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated string from fuzz input
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Test cJSON_Minify
    char *minified_str = (char *)malloc(size + 1);
    if (minified_str != NULL) {
        strcpy(minified_str, input_str);
        cJSON_Minify(minified_str);  // Modifies the string in place
        
        // Test cJSON_Parse with original string
        cJSON *parsed_json = cJSON_Parse(input_str);
        
        // Also try parsing the minified version
        cJSON *parsed_minified_json = NULL;
        if (strlen(minified_str) > 0) {
            parsed_minified_json = cJSON_Parse(minified_str);
        }

        // Test cJSON_Print with both parsed versions
        char *printed_str = NULL;
        char *printed_minified_str = NULL;
        
        if (parsed_json != NULL) {
            printed_str = cJSON_Print(parsed_json);
            
            // Test cJSON_GetStringValue if the root is a string
            if (cJSON_IsString(parsed_json)) {
                const char *str_value = cJSON_GetStringValue(parsed_json);
                // Just read the value - no specific action needed
            }
        }
        
        if (parsed_minified_json != NULL) {
            printed_minified_str = cJSON_Print(parsed_minified_json);
            
            // Test cJSON_GetStringValue if the root is a string
            if (cJSON_IsString(parsed_minified_json)) {
                const char *str_value = cJSON_GetStringValue(parsed_minified_json);
                // Just read the value - no specific action needed
            }
        }

        // Test cJSON_CreateString
        cJSON *created_string = cJSON_CreateString("test_string");
        if (created_string != NULL) {
            // Test cJSON_GetStringValue on the created string
            const char *created_str_value = cJSON_GetStringValue(created_string);
            // Just read the value - no specific action needed
        }

        // Clean up all allocated resources
        if (printed_str != NULL) {
            free(printed_str);
        }
        
        if (printed_minified_str != NULL) {
            free(printed_minified_str);
        }
        
        if (parsed_json != NULL) {
            cJSON_Delete(parsed_json);
        }
        
        if (parsed_minified_json != NULL) {
            cJSON_Delete(parsed_minified_json);
        }
        
        if (created_string != NULL) {
            cJSON_Delete(created_string);
        }
    }

    free(input_str);
    if (minified_str != NULL) {
        free(minified_str);
    }

    return 0;
}
