#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This driver tests various parsing and serialization functions with random input data

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be meaningful
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated copy of the input data for use with cJSON functions
    char* input_str = (char*)malloc(size + 1);
    if (input_str == NULL) {
        return 0; // Allocation failed, return gracefully
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0'; // Null terminate for string operations

    cJSON* parsed_json = NULL;
    char* printed_json = NULL;
    const char* error_ptr = NULL;
    const char* parse_end = NULL;

    // Test cJSON_Parse - basic JSON parsing
    parsed_json = cJSON_Parse(input_str);
    if (parsed_json != NULL) {
        // If parsing succeeded, try to print/serialize back to string
        printed_json = cJSON_Print(parsed_json);
        if (printed_json != NULL) {
            // Free the printed string to prevent memory leak
            free(printed_json);
            printed_json = NULL;
        }
        
        // Clean up the parsed JSON object
        cJSON_Delete(parsed_json);
        parsed_json = NULL;
    } else {
        // If parsing failed, get the error pointer to see what went wrong
        error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            // Just read the error pointer value - no special action needed
            volatile char dummy = *error_ptr; // Prevent compiler optimization
        }
    }

    // Test cJSON_ParseWithLength - parse with explicit length
    parsed_json = cJSON_ParseWithLength(input_str, size);
    if (parsed_json != NULL) {
        // Try to print the parsed JSON
        printed_json = cJSON_Print(parsed_json);
        if (printed_json != NULL) {
            free(printed_json);
            printed_json = NULL;
        }
        
        // Clean up the parsed JSON object
        cJSON_Delete(parsed_json);
        parsed_json = NULL;
    }

    // Test cJSON_ParseWithLengthOpts - with options
    // Try with require_null_terminated = false
    parsed_json = cJSON_ParseWithLengthOpts(input_str, size, &parse_end, 0);
    if (parsed_json != NULL) {
        // Try to print the parsed JSON
        printed_json = cJSON_Print(parsed_json);
        if (printed_json != NULL) {
            free(printed_json);
            printed_json = NULL;
        }
        
        // Clean up the parsed JSON object
        cJSON_Delete(parsed_json);
        parsed_json = NULL;
    }

    // Try with require_null_terminated = true
    parsed_json = cJSON_ParseWithLengthOpts(input_str, size, &parse_end, 1);
    if (parsed_json != NULL) {
        // Try to print the parsed JSON
        printed_json = cJSON_Print(parsed_json);
        if (printed_json != NULL) {
            free(printed_json);
            printed_json = NULL;
        }
        
        // Clean up the parsed JSON object
        cJSON_Delete(parsed_json);
        parsed_json = NULL;
    } else {
        // If parsing failed, get the error pointer
        error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            volatile char dummy = *error_ptr; // Prevent compiler optimization
        }
    }

    // If parse_end was set by ParseWithLengthOpts, check its validity
    if (parse_end != NULL) {
        // Verify parse_end is within valid range
        if (parse_end >= input_str && parse_end <= input_str + size) {
            // Valid parse_end pointer
            volatile char dummy = *parse_end; // Prevent compiler optimization
        }
    }

    // Free the input string
    free(input_str);
    input_str = NULL;

    return 0;
}
