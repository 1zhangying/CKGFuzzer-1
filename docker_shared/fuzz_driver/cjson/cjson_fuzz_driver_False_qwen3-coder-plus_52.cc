#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library
// Tests parsing and printing functionality with various options
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert input data to a null-terminated string for JSON parsing
    // We'll make a copy to ensure null termination
    char* json_str = nullptr;
    if (size > 0) {
        json_str = (char*)malloc(size + 1);
        if (!json_str) {
            return 0; // Allocation failed
        }
        memcpy(json_str, data, size);
        json_str[size] = '\0';
    } else {
        // Handle empty input case
        json_str = (char*)malloc(1);
        if (!json_str) {
            return 0; // Allocation failed
        }
        json_str[0] = '\0';
    }

    cJSON* parsed_json = nullptr;
    char* printed_json = nullptr;
    const char* parse_end = nullptr;
    
    // Test cJSON_ParseWithLength - parse with explicit length
    if (size > 0) {
        parsed_json = cJSON_ParseWithLength(json_str, size);
        
        if (parsed_json != nullptr) {
            // Test cJSON_Print - convert back to string
            printed_json = cJSON_Print(parsed_json);
            
            if (printed_json != nullptr) {
                // Successfully parsed and printed
                free(printed_json);
                printed_json = nullptr;
            }
            
            // Clean up parsed JSON
            cJSON_Delete(parsed_json);
            parsed_json = nullptr;
        } else {
            // Parsing failed, check error pointer
            const char* error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != nullptr) {
                // Error occurred, error_ptr points to location
                // No special action needed here
            }
        }
    }
    
    // Test cJSON_ParseWithOpts with different options
    if (size > 0) {
        // Try parsing with null termination required
        parsed_json = cJSON_ParseWithOpts(json_str, &parse_end, 1);
        if (parsed_json != nullptr) {
            cJSON_Delete(parsed_json);
            parsed_json = nullptr;
        } else {
            const char* error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != nullptr) {
                // Handle error if needed
            }
        }
        
        // Try parsing with null termination not required
        parsed_json = cJSON_ParseWithOpts(json_str, &parse_end, 0);
        if (parsed_json != nullptr) {
            printed_json = cJSON_Print(parsed_json);
            if (printed_json != nullptr) {
                free(printed_json);
                printed_json = nullptr;
            }
            cJSON_Delete(parsed_json);
            parsed_json = nullptr;
        }
    }
    
    // Test cJSON_ParseWithLengthOpts with different options
    if (size > 0) {
        // Parse with null termination required
        parsed_json = cJSON_ParseWithLengthOpts(json_str, size, &parse_end, 1);
        if (parsed_json != nullptr) {
            // Get error ptr even when successful (should be unchanged)
            const char* error_ptr = cJSON_GetErrorPtr();
            
            printed_json = cJSON_Print(parsed_json);
            if (printed_json != nullptr) {
                free(printed_json);
                printed_json = nullptr;
            }
            cJSON_Delete(parsed_json);
            parsed_json = nullptr;
        } else {
            const char* error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != nullptr) {
                // Handle error
            }
        }
        
        // Parse with null termination not required
        parsed_json = cJSON_ParseWithLengthOpts(json_str, size, &parse_end, 0);
        if (parsed_json != nullptr) {
            printed_json = cJSON_Print(parsed_json);
            if (printed_json != nullptr) {
                // Print again to test multiple prints
                char* second_print = cJSON_Print(parsed_json);
                if (second_print != nullptr) {
                    free(second_print);
                    second_print = nullptr;
                }
                free(printed_json);
                printed_json = nullptr;
            }
            cJSON_Delete(parsed_json);
            parsed_json = nullptr;
        } else {
            const char* error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != nullptr) {
                // Handle error
            }
        }
    }
    
    // Additional test: try to parse with minimal data
    if (size >= 2) {
        // Create a small substring to test
        char* sub_str = (char*)malloc(3);
        if (sub_str) {
            memcpy(sub_str, json_str, 2);
            sub_str[2] = '\0';
            
            parsed_json = cJSON_ParseWithLength(sub_str, 2);
            if (parsed_json != nullptr) {
                cJSON_Delete(parsed_json);
                parsed_json = nullptr;
            }
            
            free(sub_str);
        }
    }
    
    // Free the initial string
    free(json_str);
    json_str = nullptr;
    
    return 0;
}
