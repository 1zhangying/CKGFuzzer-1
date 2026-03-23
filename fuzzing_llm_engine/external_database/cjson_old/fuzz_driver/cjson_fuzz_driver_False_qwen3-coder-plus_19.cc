#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be meaningful
    if (size == 0) {
        return 0;
    }

    // Create a copy of the input data as a null-terminated string for parsing
    char* input_str = (char*)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Parse the input string as JSON with length specification
    cJSON* parsed_json = cJSON_ParseWithLength(input_str, size);
    
    // Create a new JSON object to work with
    cJSON* obj = cJSON_CreateObject();
    if (!obj) {
        free(input_str);
        if (parsed_json) {
            cJSON_Delete(parsed_json);
        }
        return 0;
    }

    // If parsing was successful, try to print it
    if (parsed_json) {
        char* printed_json = cJSON_Print(parsed_json);
        if (printed_json) {
            // Free the printed result to prevent memory leak
            free(printed_json);
        }
        
        // Add the parsed JSON as an item to our new object
        // We'll use a fixed key name since we need to extract a string from fuzz input
        cJSON_AddItemToObject(obj, "parsed_data", parsed_json);
    }

    // Create a null value and add it to the object
    cJSON* null_value = cJSON_CreateNull();
    if (null_value) {
        cJSON_AddItemToObject(obj, "null_value", null_value);
    }

    // Print the final constructed object
    char* final_printed = cJSON_Print(obj);
    if (final_printed) {
        // Free the printed result
        free(final_printed);
    }

    // Clean up all allocated resources
    cJSON_Delete(obj);
    free(input_str);

    return 0;
}
