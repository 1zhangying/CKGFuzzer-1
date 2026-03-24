#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver that tests cJSON APIs: CreateArray, Duplicate, Compare, PrintBuffered, Parse
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be useful
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from input data
    char *input_str = (char *)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Test cJSON_CreateArray
    cJSON *array = cJSON_CreateArray();
    if (!array) {
        free(input_str);
        return 0;
    }

    // Test cJSON_Parse with input string
    cJSON *parsed_json = cJSON_Parse(input_str);
    
    // If parsing was successful, perform additional tests
    if (parsed_json) {
        // Test cJSON_Duplicate - duplicate the parsed JSON
        cJSON *duplicated_json = cJSON_Duplicate(parsed_json, true);
        
        if (duplicated_json) {
            // Test cJSON_Compare - compare original with duplicate
            cJSON_bool are_equal = cJSON_Compare(parsed_json, duplicated_json, true);
            
            // Test cJSON_PrintBuffered - serialize the original with different buffer sizes
            for (int prebuffer_size = 1; prebuffer_size <= 1024; prebuffer_size *= 4) {
                char *serialized = cJSON_PrintBuffered(parsed_json, prebuffer_size, true);
                if (serialized) {
                    free(serialized);
                }
                
                // Also try with formatted output
                serialized = cJSON_PrintBuffered(parsed_json, prebuffer_size, false);
                if (serialized) {
                    free(serialized);
                }
            }
            
            // Clean up duplicated JSON
            cJSON_Delete(duplicated_json);
        }
        
        // Test cJSON_PrintBuffered with the parsed JSON
        char *json_string = cJSON_PrintBuffered(parsed_json, 256, true);
        if (json_string) {
            free(json_string);
        }
        
        // Clean up parsed JSON
        cJSON_Delete(parsed_json);
    }
    
    // Test cJSON_PrintBuffered with the created array
    char *array_string = cJSON_PrintBuffered(array, 256, true);
    if (array_string) {
        free(array_string);
    }
    
    // Clean up the created array
    cJSON_Delete(array);

    // Clean up input string
    free(input_str);
    
    return 0;
}
