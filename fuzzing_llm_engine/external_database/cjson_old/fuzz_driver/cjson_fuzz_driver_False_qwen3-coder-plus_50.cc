#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests multiple cJSON APIs including parsing, printing, and error handling
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated copy of the input data for string operations
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    cJSON *parsed_json = NULL;
    char *printed_json = NULL;
    const char *error_ptr = NULL;
    const char *parse_end = NULL;

    // Use first byte to determine which parsing method to use
    uint8_t mode = input_str[0];
    
    switch (mode % 6) {
        case 0:
            // Test cJSON_Parse
            parsed_json = cJSON_Parse(input_str);
            break;
            
        case 1:
            // Test cJSON_ParseWithLength
            if (size > 1) {
                parsed_json = cJSON_ParseWithLength(input_str + 1, size - 1);
            }
            break;
            
        case 2:
            // Test cJSON_ParseWithLengthOpts with require_null_terminated = false
            if (size > 1) {
                parsed_json = cJSON_ParseWithLengthOpts(input_str + 1, size - 1, &parse_end, 0);
            }
            break;
            
        case 3:
            // Test cJSON_ParseWithLengthOpts with require_null_terminated = true
            if (size > 1) {
                parsed_json = cJSON_ParseWithLengthOpts(input_str + 1, size - 1, &parse_end, 1);
            }
            break;
            
        case 4:
            // Test with a subset of the data
            if (size > 2) {
                size_t sub_size = (data[1] % (size - 1)) + 1;  // Ensure sub_size is at least 1
                parsed_json = cJSON_ParseWithLength(input_str + 2, sub_size);
            }
            break;
            
        case 5:
            // Test parsing the full string again but with opts
            parsed_json = cJSON_ParseWithLengthOpts(input_str, size, &parse_end, 0);
            break;
    }

    // Check for parsing errors
    error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL) {
        // Parsing failed, error message available at error_ptr
        // Note: We don't print the error since it might not be null-terminated in our context
    }

    // If parsing was successful, try printing the JSON
    if (parsed_json != NULL) {
        printed_json = cJSON_Print(parsed_json);
        
        // Free the printed JSON if it was created
        if (printed_json != NULL) {
            free(printed_json);
            printed_json = NULL;
        }
        
        // Clean up the parsed JSON
        cJSON_Delete(parsed_json);
        parsed_json = NULL;
    }
    // In case of parsing failure but no error returned by GetErrorPtr,
    // we still need to check if parsed_json is not NULL
    else if (error_ptr == NULL) {
        // This shouldn't happen in normal circumstances, 
        // but if parsing failed and no error ptr is set, just continue
    }

    // Clean up input string
    free(input_str);
    input_str = NULL;

    return 0;
}
