#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library APIs
// This driver tests the following APIs:
// - cJSON_GetArrayItem
// - cJSON_CreateStringArray
// - cJSON_PrintUnformatted
// - cJSON_CreateRaw
// - cJSON_Minify
// - cJSON_ParseWithOpts

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated string from input data
    char* input_str = (char*)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Test cJSON_ParseWithOpts
    const char* parse_end = NULL;
    cJSON* parsed_json = cJSON_ParseWithOpts(input_str, &parse_end, 0);

    // Test cJSON_Minify - make a copy since minify modifies the string in place
    char* minified_str = (char*)malloc(size + 1);
    if (minified_str) {
        strcpy(minified_str, input_str);
        cJSON_Minify(minified_str);
        
        // Try parsing the minified string too
        cJSON* minified_parsed = cJSON_ParseWithOpts(minified_str, NULL, 0);
        if (minified_parsed) {
            // Test cJSON_PrintUnformatted on minified parsed json
            char* printed_unformatted = cJSON_PrintUnformatted(minified_parsed);
            if (printed_unformatted) {
                free(printed_unformatted);
            }
            cJSON_Delete(minified_parsed);
        }
    }

    // Test cJSON_CreateRaw
    cJSON* raw_json = cJSON_CreateRaw(input_str);
    if (raw_json) {
        char* raw_printed = cJSON_PrintUnformatted(raw_json);
        if (raw_printed) {
            free(raw_printed);
        }
        cJSON_Delete(raw_json);
    }

    // Create string array for testing cJSON_CreateStringArray and cJSON_GetArrayItem
    // Extract up to 5 strings from input data to form an array
    const char* string_arr[5] = {NULL};
    size_t pos = 0;
    int count = 0;
    
    while (pos < size && count < 5) {
        // Find next null terminator or end of data
        size_t len = 0;
        while (pos + len < size && input_str[pos + len] != '\0' && input_str[pos + len] != '\n') {
            len++;
        }
        
        if (len > 0) {
            // Temporarily terminate string to store in array
            input_str[pos + len] = '\0';
            string_arr[count] = &input_str[pos];
            count++;
            pos += len + 1; // Move past the string and separator
        } else {
            pos++; // Skip null or newline character
        }
    }

    if (count > 0) {
        cJSON* string_array = cJSON_CreateStringArray(string_arr, count);
        if (string_array) {
            // Test cJSON_GetArrayItem
            for (int i = 0; i < count && i < 10; i++) {  // Limit iterations to prevent excessive processing
                cJSON* item = cJSON_GetArrayItem(string_array, i);
                if (item) {
                    // Do something with the retrieved item if needed
                    char* item_str = cJSON_PrintUnformatted(item);
                    if (item_str) {
                        free(item_str);
                    }
                }
            }
            
            // Also test with potentially out-of-bounds index
            cJSON* invalid_item = cJSON_GetArrayItem(string_array, count + 5);
            if (invalid_item != NULL) {
                // Should not happen, but handle just in case
            }
            
            cJSON_Delete(string_array);
        }
    }

    // Clean up parsed JSON if it was created
    if (parsed_json) {
        char* printed = cJSON_PrintUnformatted(parsed_json);
        if (printed) {
            free(printed);
        }
        cJSON_Delete(parsed_json);
    }

    // Free allocated memory
    free(input_str);
    if (minified_str) {
        free(minified_str);
    }

    return 0;
}
