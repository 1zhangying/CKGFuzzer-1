#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to work with
    if (size < 1) {
        return 0;
    }

    // Create a copy of input data to work with
    char* input_data = (char*)malloc(size + 1);
    if (!input_data) {
        return 0;
    }
    
    memcpy(input_data, data, size);
    input_data[size] = '\0'; // Null terminate for string operations

    cJSON* root = NULL;
    char* json_string = NULL;
    char* json_formatted = NULL;
    char* json_unformatted = NULL;
    char* json_buffered = NULL;
    char preallocated_buffer[1024];
    bool print_result = false;

    // Try parsing the input as JSON first
    root = cJSON_Parse(input_data);
    if (!root) {
        // If parsing fails, create a basic object/array structure for testing APIs
        // Decide based on first byte whether to create object or array
        if (input_data[0] % 2 == 0) {
            root = cJSON_CreateObject();
        } else {
            root = cJSON_CreateArray();
        }
        
        // If even creating basic structure fails, exit early
        if (!root) {
            free(input_data);
            return 0;
        }
    }

    // Test cJSON_Print - creates formatted JSON string
    json_formatted = cJSON_Print(root);
    if (json_formatted != NULL) {
        // Free the string returned by cJSON_Print
        cJSON_free(json_formatted);
    }

    // Test cJSON_PrintUnformatted - creates unformatted JSON string
    json_unformatted = cJSON_PrintUnformatted(root);
    if (json_unformatted != NULL) {
        // Free the string returned by cJSON_PrintUnformatted
        cJSON_free(json_unformatted);
    }

    // Test cJSON_PrintBuffered with different prebuffer sizes
    int prebuffer_size = 0;
    if (size > 0) {
        prebuffer_size = input_data[0] % 256; // Use first byte to determine prebuffer size
        if (prebuffer_size < 0) prebuffer_size = -prebuffer_size;
    }
    
    json_buffered = cJSON_PrintBuffered(root, prebuffer_size, true);
    if (json_buffered != NULL) {
        // Free the string returned by cJSON_PrintBuffered
        cJSON_free(json_buffered);
    }

    // Test cJSON_PrintPreallocated with preallocated buffer
    memset(preallocated_buffer, 0, sizeof(preallocated_buffer));
    print_result = cJSON_PrintPreallocated(root, preallocated_buffer, sizeof(preallocated_buffer), true);
    // Print result is boolean indicating success/failure, no memory to free

    // Test with different formatting option
    memset(preallocated_buffer, 0, sizeof(preallocated_buffer));
    print_result = cJSON_PrintPreallocated(root, preallocated_buffer, sizeof(preallocated_buffer), false);

    // Clean up: delete the root JSON object and free input data
    if (root) {
        cJSON_Delete(root);
    }

    free(input_data);
    
    return 0;
}
