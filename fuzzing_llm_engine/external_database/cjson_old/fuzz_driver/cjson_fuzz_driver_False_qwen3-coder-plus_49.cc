#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a null-terminated string for JSON parsing
    if (size == 0) {
        return 0; // Nothing to process
    }

    // Create a copy of the input data with null termination for safe string operations
    char* json_str = (char*)malloc(size + 1);
    if (!json_str) {
        return 0; // Allocation failed
    }
    
    memcpy(json_str, data, size);
    json_str[size] = '\0';

    // Initialize variables for different parsing functions
    cJSON* parsed_json = nullptr;
    cJSON* parsed_with_opts = nullptr;
    cJSON* parsed_with_length = nullptr;
    cJSON* parsed_with_length_opts = nullptr;
    char* printed_json = nullptr;
    const char* parse_end = nullptr;

    // Test cJSON_Parse (basic parsing)
    parsed_json = cJSON_Parse(json_str);
    if (parsed_json != nullptr) {
        // Test cJSON_Print with the parsed result
        printed_json = cJSON_Print(parsed_json);
        if (printed_json != nullptr) {
            // Free the printed result
            free(printed_json);
            printed_json = nullptr;
        }
        
        // Clean up parsed JSON
        cJSON_Delete(parsed_json);
        parsed_json = nullptr;
    }

    // Test cJSON_ParseWithOpts (with options)
    parsed_with_opts = cJSON_ParseWithOpts(json_str, &parse_end, 0); // Don't require null termination
    if (parsed_with_opts != nullptr) {
        // Test cJSON_Print with the parsed result
        printed_json = cJSON_Print(parsed_with_opts);
        if (printed_json != nullptr) {
            // Free the printed result
            free(printed_json);
            printed_json = nullptr;
        }
        
        // Clean up parsed JSON
        cJSON_Delete(parsed_with_opts);
        parsed_with_opts = nullptr;
    }

    // Test cJSON_ParseWithLength (with explicit length)
    parsed_with_length = cJSON_ParseWithLength(json_str, size);
    if (parsed_with_length != nullptr) {
        // Test cJSON_Print with the parsed result
        printed_json = cJSON_Print(parsed_with_length);
        if (printed_json != nullptr) {
            // Free the printed result
            free(printed_json);
            printed_json = nullptr;
        }
        
        // Clean up parsed JSON
        cJSON_Delete(parsed_with_length);
        parsed_with_length = nullptr;
    }

    // Test cJSON_ParseWithLengthOpts (with length and options)
    parsed_with_length_opts = cJSON_ParseWithLengthOpts(json_str, size, &parse_end, 0); // Don't require null termination
    if (parsed_with_length_opts != nullptr) {
        // Test cJSON_Print with the parsed result
        printed_json = cJSON_Print(parsed_with_length_opts);
        if (printed_json != nullptr) {
            // Free the printed result
            free(printed_json);
            printed_json = nullptr;
        }
        
        // Clean up parsed JSON
        cJSON_Delete(parsed_with_length_opts);
        parsed_with_length_opts = nullptr;
    }

    // Test with require_null_terminated = 1 (true)
    parsed_with_length_opts = cJSON_ParseWithLengthOpts(json_str, size, nullptr, 1); 
    if (parsed_with_length_opts != nullptr) {
        // Test cJSON_Print with the parsed result
        printed_json = cJSON_Print(parsed_with_length_opts);
        if (printed_json != nullptr) {
            // Free the printed result
            free(printed_json);
            printed_json = nullptr;
        }
        
        // Clean up parsed JSON
        cJSON_Delete(parsed_with_length_opts);
        parsed_with_length_opts = nullptr;
    }

    // Additional test with parse end position
    parsed_with_length_opts = cJSON_ParseWithLengthOpts(json_str, size, &parse_end, 0);
    if (parsed_with_length_opts != nullptr) {
        // Test cJSON_Print with the parsed result
        printed_json = cJSON_Print(parsed_with_length_opts);
        if (printed_json != nullptr) {
            // Free the printed result
            free(printed_json);
            printed_json = nullptr;
        }
        
        // Clean up parsed JSON
        cJSON_Delete(parsed_with_length_opts);
        parsed_with_length_opts = nullptr;
    }

    // Clean up allocated string
    free(json_str);
    json_str = nullptr;

    return 0;
}
