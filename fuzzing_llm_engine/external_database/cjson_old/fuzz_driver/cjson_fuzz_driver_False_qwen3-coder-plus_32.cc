#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// Tests multiple parsing and printing functions with error handling
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated copy of the input data for string operations
    char *input_str = (char*)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Test cJSON_Parse - basic parsing function
    cJSON *json1 = cJSON_Parse(input_str);
    if (json1 != NULL) {
        // Test cJSON_Print - convert parsed JSON back to string
        char *output_str1 = cJSON_Print(json1);
        if (output_str1 != NULL) {
            // Free the printed string
            free(output_str1);
        }
        // Clean up parsed JSON object
        cJSON_Delete(json1);
    } else {
        // If parsing failed, check error location
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            // Use error pointer but don't do anything with it
            // This just ensures the function is called
        }
    }

    // Test cJSON_ParseWithLength - parsing with explicit buffer length
    cJSON *json2 = cJSON_ParseWithLength(input_str, size);
    if (json2 != NULL) {
        // Test cJSON_Print again with this parsed object
        char *output_str2 = cJSON_Print(json2);
        if (output_str2 != NULL) {
            // Free the printed string
            free(output_str2);
        }
        // Clean up parsed JSON object
        cJSON_Delete(json2);
    }

    // Test cJSON_ParseWithOpts - parsing with options
    const char *parse_end = NULL;
    cJSON *json3 = cJSON_ParseWithOpts(input_str, &parse_end, 0); // require_null_terminated = false
    if (json3 != NULL) {
        // Test cJSON_Print again with this parsed object
        char *output_str3 = cJSON_Print(json3);
        if (output_str3 != NULL) {
            // Free the printed string
            free(output_str3);
        }
        // Clean up parsed JSON object
        cJSON_Delete(json3);
    } else {
        // If parsing failed, check error location
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            // Use error pointer but don't do anything with it
            // This just ensures the function is called
        }
    }

    // Additional test: Try parsing with require_null_terminated = true
    // Only if the input doesn't already have a null terminator within the size range
    if (size > 0 && memchr(input_str, '\0', size - 1) == NULL) {
        // Add a null terminator at the end to make it valid for null-terminated parsing
        char *temp_str = (char*)malloc(size + 1);
        if (temp_str) {
            memcpy(temp_str, input_str, size);
            temp_str[size] = '\0';
            
            cJSON *json4 = cJSON_ParseWithOpts(temp_str, NULL, 1); // require_null_terminated = true
            if (json4 != NULL) {
                char *output_str4 = cJSON_Print(json4);
                if (output_str4 != NULL) {
                    free(output_str4);
                }
                cJSON_Delete(json4);
            } else {
                // Check error location if parsing failed
                const char *error_ptr = cJSON_GetErrorPtr();
                if (error_ptr != NULL) {
                    // Use error pointer but don't do anything with it
                }
            }
            free(temp_str);
        }
    }

    // Clean up the original input string
    free(input_str);

    return 0;
}
