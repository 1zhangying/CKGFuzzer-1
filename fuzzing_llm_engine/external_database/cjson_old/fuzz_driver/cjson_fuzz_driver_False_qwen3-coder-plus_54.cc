#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests multiple cJSON APIs including parsing, printing, and creation functions
// It handles all possible error cases and ensures proper memory management

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be meaningful
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *input_str = (char *)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Test cJSON_Parse - Parse the input string as JSON
    cJSON *parsed_json = cJSON_Parse(input_str);
    
    // Test cJSON_CreateObject - Create a new JSON object regardless of parse result
    cJSON *obj = cJSON_CreateObject();
    
    // If parsing was successful, perform additional operations with the parsed JSON
    if (parsed_json != NULL) {
        // Test cJSON_Print - Print formatted version of parsed JSON
        char *formatted_output = cJSON_Print(parsed_json);
        if (formatted_output != NULL) {
            free(formatted_output); // Free the allocated string
        }
        
        // Test cJSON_PrintUnformatted - Print unformatted version of parsed JSON
        char *unformatted_output = cJSON_PrintUnformatted(parsed_json);
        if (unformatted_output != NULL) {
            free(unformatted_output); // Free the allocated string
        }
        
        // Test cJSON_PrintBuffered - Print with custom buffer settings
        char *buffered_output = cJSON_PrintBuffered(parsed_json, 256, true);
        if (buffered_output != NULL) {
            free(buffered_output); // Free the allocated string
        }
        
        // Test cJSON_PrintPreallocated - Print to pre-allocated buffer
        char prealloc_buffer[512];
        cJSON_bool print_result = cJSON_PrintPreallocated(parsed_json, prealloc_buffer, sizeof(prealloc_buffer), true);
        (void)print_result; // Suppress unused variable warning
        
        // Clean up the parsed JSON object
        cJSON_Delete(parsed_json);
    }
    
    // Perform operations on the created object (even if parsing failed)
    if (obj != NULL) {
        // Test cJSON_Print with the created object
        char *obj_formatted = cJSON_Print(obj);
        if (obj_formatted != NULL) {
            free(obj_formatted); // Free the allocated string
        }
        
        // Test cJSON_PrintUnformatted with the created object
        char *obj_unformatted = cJSON_PrintUnformatted(obj);
        if (obj_unformatted != NULL) {
            free(obj_unformatted); // Free the allocated string
        }
        
        // Test cJSON_PrintBuffered with the created object
        char *obj_buffered = cJSON_PrintBuffered(obj, 128, false);
        if (obj_buffered != NULL) {
            free(obj_buffered); // Free the allocated string
        }
        
        // Test cJSON_PrintPreallocated with the created object
        char obj_prealloc_buffer[256];
        cJSON_bool obj_print_result = cJSON_PrintPreallocated(obj, obj_prealloc_buffer, sizeof(obj_prealloc_buffer), false);
        (void)obj_print_result; // Suppress unused variable warning
        
        // Clean up the created object
        cJSON_Delete(obj);
    }
    
    // Free the input string
    free(input_str);
    
    return 0;
}
