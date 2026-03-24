#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzzer tests multiple cJSON APIs to achieve comprehensive coverage
// including parsing, printing with different formats, and object creation

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to null-terminated string for JSON parsing
    if (size == 0) {
        return 0;
    }
    
    // Create a copy of the input data with null terminator for safe string operations
    char *input_str = (char *)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';
    
    cJSON *parsed_json = NULL;
    char *printed_json = NULL;
    char *buffered_json = NULL;
    char *unformatted_json = NULL;
    char *preallocated_buffer = NULL;
    cJSON *created_obj = NULL;
    
    // Test cJSON_Parse - parse the input string as JSON
    parsed_json = cJSON_Parse(input_str);
    
    // Test cJSON_CreateObject - create a new empty object
    created_obj = cJSON_CreateObject();
    
    if (parsed_json != NULL) {
        // Test cJSON_Print - print formatted JSON string
        printed_json = cJSON_Print(parsed_json);
        
        // Test cJSON_PrintUnformatted - print unformatted JSON string
        unformatted_json = cJSON_PrintUnformatted(parsed_json);
        
        // Test cJSON_PrintBuffered with different prebuffer sizes
        int prebuffer_size = 1024; // Start with a reasonable buffer size
        if (size > 0) {
            // Derive prebuffer size from input data
            prebuffer_size = (int)(data[0]) + 1; // Ensure it's not zero
        }
        buffered_json = cJSON_PrintBuffered(parsed_json, prebuffer_size, 1); // Formatted
        
        // Test cJSON_PrintPreallocated - print to pre-allocated buffer
        int print_length = 2048; // Buffer size for preallocated print
        if (size >= sizeof(int)) {
            // Derive length from input data (using first 4 bytes as integer if available)
            if (size >= sizeof(int)) {
                print_length = *((int*)(data)) % 4096; // Keep within reasonable range
                if (print_length <= 0) print_length = 1024;
            }
        }
        
        preallocated_buffer = (char *)malloc(print_length);
        if (preallocated_buffer != NULL) {
            cJSON_bool format = (size > 0 && (data[0] % 2 == 0)) ? 1 : 0; // Determine format from input
            cJSON_PrintPreallocated(parsed_json, preallocated_buffer, print_length, format);
        }
        
        // Clean up individual results
        if (printed_json != NULL) {
            free(printed_json);
            printed_json = NULL;
        }
        
        if (unformatted_json != NULL) {
            free(unformatted_json);
            unformatted_json = NULL;
        }
        
        if (buffered_json != NULL) {
            free(buffered_json);
            buffered_json = NULL;
        }
        
        if (preallocated_buffer != NULL) {
            free(preallocated_buffer);
            preallocated_buffer = NULL;
        }
        
        // Clean up parsed JSON
        cJSON_Delete(parsed_json);
        parsed_json = NULL;
    }
    
    // Clean up created object if it was created successfully
    if (created_obj != NULL) {
        cJSON_Delete(created_obj);
        created_obj = NULL;
    }
    
    // Clean up input string
    free(input_str);
    input_str = NULL;
    
    return 0;
}
