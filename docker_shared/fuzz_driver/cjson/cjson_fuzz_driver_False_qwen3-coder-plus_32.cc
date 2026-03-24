#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be meaningful
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) {
        return 0; // Early return on allocation failure
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Test cJSON_Parse - Parse the input string as JSON
    cJSON *parsed_json = cJSON_Parse(input_str);
    
    // Check for parsing errors using cJSON_GetErrorPtr
    const char *error_ptr = cJSON_GetErrorPtr();
    if (parsed_json == NULL && error_ptr != NULL) {
        // Parsing failed, error_ptr points to the error location
        // We can still continue testing other functionality
    }

    // Test cJSON_CreateObject - Create a new JSON object
    cJSON *obj1 = cJSON_CreateObject();
    if (obj1 != NULL) {
        // If we have a successfully parsed JSON object, try to compare
        if (parsed_json != NULL) {
            // Test cJSON_Compare - Compare the parsed JSON with the created object
            cJSON_bool are_equal = cJSON_Compare(parsed_json, obj1, cJSON_True);
            
            // Also try comparing with case insensitive option
            cJSON_bool are_equal_ci = cJSON_Compare(parsed_json, obj1, cJSON_False);
            
            // Try self-comparison (should always be true)
            cJSON_bool self_compare = cJSON_Compare(parsed_json, parsed_json, cJSON_True);
        }
        
        // Clean up the created object
        cJSON_Delete(obj1);
    }

    // Clean up the parsed JSON if it was successfully created
    if (parsed_json != NULL) {
        cJSON_Delete(parsed_json);
    }

    // Free the input string
    free(input_str);

    return 0;
}
