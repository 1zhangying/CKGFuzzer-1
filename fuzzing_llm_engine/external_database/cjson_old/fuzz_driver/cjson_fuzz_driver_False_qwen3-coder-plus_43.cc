#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// Tests parsing, printing, number operations, and null checks

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert input data to null-terminated string for JSON parsing
    if (size == 0) {
        return 0;
    }

    // Allocate memory for null-terminated string
    char* json_string = (char*)malloc(size + 1);
    if (!json_string) {
        return 0;
    }

    // Copy input data and add null terminator
    memcpy(json_string, data, size);
    json_string[size] = '\0';

    // Parse the JSON string
    cJSON* root = cJSON_Parse(json_string);
    
    // Free the temporary string since we no longer need it
    free(json_string);

    // Test cJSON_IsNull on the root element
    if (root != NULL) {
        int is_null = cJSON_IsNull(root);
        
        // If the parsed JSON is a number, test number-related APIs
        if (cJSON_IsNumber(root)) {
            double number_value = cJSON_GetNumberValue(root);
            
            // Create a new number based on the extracted value
            cJSON* new_number = cJSON_CreateNumber(number_value);
            if (new_number != NULL) {
                // Verify the created number is indeed a number
                if (cJSON_IsNumber(new_number)) {
                    double new_number_value = cJSON_GetNumberValue(new_number);
                    
                    // Print the new number to test cJSON_Print
                    char* printed_json = cJSON_Print(new_number);
                    if (printed_json != NULL) {
                        // Free the printed JSON string
                        free(printed_json);
                    }
                }
                
                // Clean up the created number
                cJSON_Delete(new_number);
            }
        }
        
        // Test cJSON_Print on the original parsed JSON
        char* printed_json = cJSON_Print(root);
        if (printed_json != NULL) {
            // Free the printed JSON string
            free(printed_json);
        }
        
        // Clean up the parsed JSON
        cJSON_Delete(root);
    } else {
        // If parsing failed, try creating a simple number as fallback
        cJSON* fallback_number = cJSON_CreateNumber(42.0);
        if (fallback_number != NULL) {
            if (cJSON_IsNumber(fallback_number)) {
                double value = cJSON_GetNumberValue(fallback_number);
                
                // Print the fallback number
                char* printed_json = cJSON_Print(fallback_number);
                if (printed_json != NULL) {
                    free(printed_json);
                }
            }
            cJSON_Delete(fallback_number);
        }
    }

    return 0;
}
