#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests multiple cJSON APIs to achieve comprehensive code coverage
// while ensuring robust error handling and proper memory management

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 1) {
        return 0;
    }

    // Convert fuzz input to a null-terminated string for JSON parsing
    char *json_string = (char *)malloc(size + 1);
    if (!json_string) {
        return 0; // Allocation failed
    }
    
    memcpy(json_string, data, size);
    json_string[size] = '\0';

    // Test 1: Parse the JSON string
    cJSON *parsed_json = cJSON_Parse(json_string);
    
    if (parsed_json != NULL) {
        // Test 2: Print the parsed JSON in formatted way
        char *formatted_output = cJSON_Print(parsed_json);
        if (formatted_output != NULL) {
            // Free the formatted output
            cJSON_free(formatted_output);
        }

        // Test 3: Print the parsed JSON in unformatted way
        char *unformatted_output = cJSON_PrintUnformatted(parsed_json);
        if (unformatted_output != NULL) {
            // Free the unformatted output
            cJSON_free(unformatted_output);
        }

        // Test 4: Print with buffered approach - first determine a reasonable buffer size
        int prebuffer_size = (size > 1024) ? 1024 : size;  // Limit buffer size to prevent excessive allocation
        char *buffered_output = cJSON_PrintBuffered(parsed_json, prebuffer_size, 1); // 1 for formatted
        if (buffered_output != NULL) {
            // Free the buffered output
            cJSON_free(buffered_output);
        }

        // Test 5: Print with preallocated buffer
        int prealloc_size = 1024;
        char *prealloc_buffer = (char *)malloc(prealloc_size);
        if (prealloc_buffer != NULL) {
            if (cJSON_PrintPreallocated(parsed_json, prealloc_buffer, prealloc_size, 1)) {
                // Successfully printed to preallocated buffer
                // No need to free prealloc_buffer as it's managed by caller
            }
            free(prealloc_buffer);
        }

        // Clean up the parsed JSON object
        cJSON_Delete(parsed_json);
    }

    // Test 6: Create an empty object
    cJSON *new_object = cJSON_CreateObject();
    if (new_object != NULL) {
        // Try to print this new object
        char *object_output = cJSON_Print(new_object);
        if (object_output != NULL) {
            cJSON_free(object_output);
        }

        // Also try unformatted print
        char *object_unformatted = cJSON_PrintUnformatted(new_object);
        if (object_unformatted != NULL) {
            cJSON_free(object_unformatted);
        }

        // Clean up the created object
        cJSON_Delete(new_object);
    }

    // Free the original input string
    free(json_string);

    return 0;
}
