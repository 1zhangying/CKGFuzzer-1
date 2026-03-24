#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// Tests the following APIs: cJSON_ParseWithLengthOpts, cJSON_AddStringToObject, 
// cJSON_CreateObject, cJSON_Compare, cJSON_PrintBuffered, cJSON_Delete

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be useful
    if (size < 10) {
        return 0;
    }

    // Split input data into multiple segments for different purposes
    size_t json_size = size / 3;
    if (json_size == 0) json_size = 1;
    
    size_t name_size = (size - json_size) / 2;
    if (name_size == 0) name_size = 1;
    
    size_t value_size = size - json_size - name_size;
    if (value_size == 0) value_size = 1;

    // Create null-terminated strings from input data
    char *json_str = (char*)malloc(json_size + 1);
    char *name_str = (char*)malloc(name_size + 1);
    char *value_str = (char*)malloc(value_size + 1);

    if (!json_str || !name_str || !value_str) {
        free(json_str);
        free(name_str);
        free(value_str);
        return 0;
    }

    memcpy(json_str, data, json_size);
    json_str[json_size] = '\0';

    memcpy(name_str, data + json_size, name_size);
    name_str[name_size] = '\0';

    memcpy(value_str, data + json_size + name_size, value_size);
    value_str[value_size] = '\0';

    // Ensure strings don't contain null bytes in the middle to avoid early termination
    for (size_t i = 0; i < json_size; ++i) {
        if (json_str[i] == '\0') {
            json_str[i] = 'A';
        }
    }
    for (size_t i = 0; i < name_size; ++i) {
        if (name_str[i] == '\0') {
            name_str[i] = 'B';
        }
    }
    for (size_t i = 0; i < value_size; ++i) {
        if (value_str[i] == '\0') {
            value_str[i] = 'C';
        }
    }

    cJSON *parsed_json = NULL;
    cJSON *object1 = NULL;
    cJSON *object2 = NULL;
    char *printed_json = NULL;
    const char *parse_end = NULL;

    // Determine flags based on input data
    cJSON_bool require_null_terminated = (size % 2 == 0) ? 1 : 0;
    cJSON_bool case_sensitive = (size % 3 == 0) ? 1 : 0;
    cJSON_bool format_output = (size % 5 == 0) ? 1 : 0;

    // Test cJSON_ParseWithLengthOpts
    parsed_json = cJSON_ParseWithLengthOpts(json_str, json_size, &parse_end, require_null_terminated);

    // Test cJSON_CreateObject
    object1 = cJSON_CreateObject();
    if (object1 == NULL) {
        // Perform cleanup before returning to avoid goto jumping over variable initialization
        if (parsed_json) {
            cJSON_Delete(parsed_json);
        }
        free(json_str);
        free(name_str);
        free(value_str);
        return 0;
    }

    // Test cJSON_AddStringToObject if parsing was successful
    if (parsed_json != NULL) {
        // Compare original parsed JSON with itself
        cJSON_bool compare_result = cJSON_Compare(parsed_json, parsed_json, case_sensitive);
        
        // Try to add a string to the parsed object if it's an object type
        if (parsed_json->type == cJSON_Object) {
            cJSON_AddStringToObject(parsed_json, name_str, value_str);
        }
    }

    // Add string to our created object
    cJSON_AddStringToObject(object1, name_str, value_str);

    // Create another object for comparison
    object2 = cJSON_CreateObject();
    if (object2 != NULL) {
        cJSON_AddStringToObject(object2, name_str, value_str);
        
        // Test cJSON_Compare
        cJSON_bool compare_result = cJSON_Compare(object1, object2, case_sensitive);
        (void)compare_result; // Suppress unused variable warning
        
        // Also compare with potentially parsed JSON if available
        if (parsed_json != NULL) {
            cJSON_Compare(parsed_json, object1, case_sensitive);
        }
    }

    // Test cJSON_PrintBuffered with different buffer sizes
    int prebuffer_size = (size % 1000) + 100; // Buffer size between 100 and 1100
    printed_json = cJSON_PrintBuffered(object1, prebuffer_size, format_output);
    
    // If printing fails, try with a larger buffer
    if (printed_json == NULL) {
        printed_json = cJSON_PrintBuffered(object1, prebuffer_size * 2, format_output);
    }

    // Clean up all allocated resources
    if (parsed_json) {
        cJSON_Delete(parsed_json);
    }
    
    if (object1) {
        cJSON_Delete(object1);
    }
    
    if (object2) {
        cJSON_Delete(object2);
    }
    
    if (printed_json) {
        free(printed_json);
    }

    free(json_str);
    free(name_str);
    free(value_str);

    return 0;
}
