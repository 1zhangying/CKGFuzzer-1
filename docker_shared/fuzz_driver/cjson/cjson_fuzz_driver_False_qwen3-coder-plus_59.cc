#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for cJSON APIs
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure minimum size for meaningful operations
    if (size < 1) {
        return 0;
    }

    // Create a copy of the input data to work with since some APIs may modify it
    char* json_input = (char*)malloc(size + 1);
    if (!json_input) {
        return 0;
    }
    
    memcpy(json_input, data, size);
    json_input[size] = '\0';

    // Test cJSON_Version - Get library version
    const char* version = cJSON_Version();
    if (version != NULL) {
        // Version string exists, we can print it if needed for debugging
        // For fuzzing purposes, just verify it's not null
    }

    // Test cJSON_GetErrorPtr - Get error pointer (initially should be empty)
    const char* error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL) {
        // Error pointer exists - this might be empty initially
    }

    // Test cJSON_CreateRaw - Create a raw cJSON item
    cJSON* raw_item = NULL;
    if (size > 0) {
        // Use part of the input as raw JSON string
        size_t raw_len = size / 2;  // Use first half as raw string
        if (raw_len == 0) raw_len = 1;
        
        char* raw_str = (char*)malloc(raw_len + 1);
        if (raw_str) {
            memcpy(raw_str, data, raw_len);
            raw_str[raw_len] = '\0';
            
            raw_item = cJSON_CreateRaw(raw_str);
            free(raw_str);
        }
    }

    // Test cJSON_IsRaw - Check if the created item is raw
    if (raw_item != NULL) {
        bool is_raw = cJSON_IsRaw(raw_item);
        // Use the result to prevent compiler optimization
        if (is_raw) {
            // Confirm that the item is indeed raw
        }
    }

    // Test cJSON_GetNumberValue - Try to get number value from the raw item
    // Note: This will likely return NaN since raw items don't have numeric values
    if (raw_item != NULL) {
        double num_value = cJSON_GetNumberValue(raw_item);
        // Use the value to prevent compiler optimization
        (void)num_value;
    }

    // Test cJSON_Minify - Minify the JSON input string
    char* minified_json = (char*)malloc(size + 1);
    if (minified_json) {
        memcpy(minified_json, data, size);
        minified_json[size] = '\0';
        
        // Perform minification
        cJSON_Minify(minified_json);
        
        // After minification, the string is modified in place
        // We can perform additional operations on the minified string
        
        // Try creating a raw item from the minified string
        cJSON* minified_raw_item = cJSON_CreateRaw(minified_json);
        if (minified_raw_item != NULL) {
            // Test if the new item is raw
            bool is_minified_raw = cJSON_IsRaw(minified_raw_item);
            (void)is_minified_raw;
            
            // Get number value from the minified raw item
            double min_num_value = cJSON_GetNumberValue(minified_raw_item);
            (void)min_num_value;
            
            // Clean up the minified raw item
            cJSON_Delete(minified_raw_item);
        }
        
        free(minified_json);
    }

    // Additional testing with parsed JSON (if possible)
    if (size > 0) {
        // Try to parse the original input as JSON
        cJSON* parsed_json = cJSON_Parse(json_input);
        if (parsed_json != NULL) {
            // Recursively test cJSON_GetNumberValue on all items
            void* current = parsed_json;
            cJSON* iter = parsed_json;
            
            // Process the root item
            if (cJSON_IsNumber(iter)) {
                double val = cJSON_GetNumberValue(iter);
                (void)val;
            }
            
            // Process children if they exist
            cJSON* child = iter->child;
            while (child != NULL) {
                if (cJSON_IsNumber(child)) {
                    double child_val = cJSON_GetNumberValue(child);
                    (void)child_val;
                }
                
                // Check if child is raw
                bool child_is_raw = cJSON_IsRaw(child);
                (void)child_is_raw;
                
                child = child->next;
            }
            
            cJSON_Delete(parsed_json);
        }
    }

    // Clean up resources
    if (raw_item != NULL) {
        cJSON_Delete(raw_item);
    }
    
    free(json_input);

    return 0;
}
