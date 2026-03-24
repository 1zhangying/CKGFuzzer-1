#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for cJSON library testing
// This fuzzer tests various cJSON operations including parsing, creating arrays,
// adding number objects, printing unformatted JSON, and proper cleanup.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be useful
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated string from input data for parsing
    char *input_str = (char *)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Test cJSON_Parse - parse the input string as JSON
    cJSON *parsed_json = cJSON_Parse(input_str);
    
    // Test cJSON_CreateArray - create an empty array
    cJSON *array_obj = cJSON_CreateArray();
    
    // Test cJSON_AddNumberToObject - only if we have parsed an object and enough data
    if (parsed_json && cJSON_IsObject(parsed_json) && size >= sizeof(double)) {
        // Extract a double value from the input data
        double number_val = 0.0;
        if (size >= sizeof(double)) {
            memcpy(&number_val, data, sizeof(double));
        }
        
        // Create a simple name string from available data (first few bytes as name)
        char name[10];
        size_t name_len = (size > 9) ? 9 : size;
        for (size_t i = 0; i < name_len; i++) {
            char c = input_str[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
                name[i] = c;
            } else {
                name[i] = '_';
            }
        }
        name[name_len] = '\0';
        
        // Add number to the parsed object
        cJSON *added_number = cJSON_AddNumberToObject(parsed_json, name, number_val);
        (void)added_number; // Suppress unused variable warning
    }
    
    // Test cJSON_CreateArray if not already done
    if (!array_obj) {
        array_obj = cJSON_CreateArray();
    }
    
    // Test adding a number to the created array if it's valid
    if (array_obj && size >= sizeof(double)) {
        double number_val = 0.0;
        if (size >= sizeof(double)) {
            memcpy(&number_val, data, sizeof(double));
        }
        
        // Create a number item and add it to array
        cJSON *number_item = cJSON_CreateNumber(number_val);
        if (number_item) {
            cJSON_AddItemToArray(array_obj, number_item);
        }
    }
    
    // Test cJSON_PrintUnformatted with both parsed and created objects
    char *unformatted_output = nullptr;
    if (parsed_json) {
        unformatted_output = cJSON_PrintUnformatted(parsed_json);
    } else if (array_obj) {
        unformatted_output = cJSON_PrintUnformatted(array_obj);
    }
    
    // Free the printed result if it was created
    if (unformatted_output) {
        cJSON_free(unformatted_output);
    }
    
    // Test cJSON_PrintUnformatted with array object specifically
    if (array_obj) {
        char *array_output = cJSON_PrintUnformatted(array_obj);
        if (array_output) {
            cJSON_free(array_output);
        }
    }
    
    // Clean up all allocated cJSON objects
    if (parsed_json) {
        cJSON_Delete(parsed_json);
    }
    
    if (array_obj) {
        cJSON_Delete(array_obj);
    }
    
    // Free the input string buffer
    free(input_str);
    
    return 0;
}
