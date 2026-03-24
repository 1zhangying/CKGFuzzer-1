#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests various cJSON APIs including parsing, duplication,
// printing, and type checking functionality

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be meaningful
    if (size < 1) {
        return 0;
    }

    // Convert input data to a null-terminated string for JSON parsing
    char* json_str = (char*)malloc(size + 1);
    if (!json_str) {
        return 0;
    }
    
    memcpy(json_str, data, size);
    json_str[size] = '\0';

    // Parse the input string as JSON
    cJSON* root = cJSON_Parse(json_str);
    
    // Check for parsing errors using cJSON_GetErrorPtr
    if (root == NULL) {
        const char* error_ptr = cJSON_GetErrorPtr();
        // Error occurred during parsing - check if error pointer is valid
        if (error_ptr != NULL) {
            // The error pointer points to the location of the error in the input
            // We don't need to do anything specific here, just acknowledge the error
        }
        
        free(json_str);
        return 0;
    }

    // Test cJSON_IsArray to check if the parsed JSON is an array
    cJSON_bool is_array = cJSON_IsArray(root);
    
    // Test cJSON_Duplicate to create a copy of the parsed JSON
    cJSON* duplicate = cJSON_Duplicate(root, true); // Deep copy
    if (duplicate != NULL) {
        // Test cJSON_IsArray on the duplicated object too
        cJSON_bool is_duplicate_array = cJSON_IsArray(duplicate);
        
        // Test cJSON_PrintBuffered with different buffer sizes and formatting options
        int prebuffer_sizes[] = {256, 512, 1024};
        for (int i = 0; i < 3; i++) {
            char* printed_buffer = cJSON_PrintBuffered(duplicate, prebuffer_sizes[i], true);
            if (printed_buffer != NULL) {
                // Successfully printed with formatting
                free(printed_buffer);
            }
            
            printed_buffer = cJSON_PrintBuffered(duplicate, prebuffer_sizes[i], false);
            if (printed_buffer != NULL) {
                // Successfully printed without formatting
                free(printed_buffer);
            }
        }
        
        // Test cJSON_PrintPreallocated with a fixed-size buffer
        char preallocated_buffer[1024];
        cJSON_bool print_result = cJSON_PrintPreallocated(duplicate, preallocated_buffer, sizeof(preallocated_buffer), true);
        if (print_result) {
            // Successfully printed to preallocated buffer with formatting
        }
        
        print_result = cJSON_PrintPreallocated(duplicate, preallocated_buffer, sizeof(preallocated_buffer), false);
        if (print_result) {
            // Successfully printed to preallocated buffer without formatting
        }
        
        // Clean up the duplicate
        cJSON_Delete(duplicate);
    }
    
    // Also test printing the original root object
    char* original_printed = cJSON_Print(root);
    if (original_printed != NULL) {
        free(original_printed);
    }
    
    // Clean up the original parsed object
    cJSON_Delete(root);
    
    // Free the input string buffer
    free(json_str);
    
    return 0;
}
