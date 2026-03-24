#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library APIs
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a null-terminated string
    if (size == 0) {
        return 0;
    }
    
    // Allocate memory for the input string and copy the data
    char* input_str = (char*)malloc(size + 1);
    if (input_str == NULL) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0'; // Null terminate
    
    // Make a copy for minify operation since it modifies the string in place
    char* minify_input = (char*)malloc(size + 1);
    if (minify_input == NULL) {
        free(input_str);
        return 0;
    }
    
    strcpy(minify_input, input_str);
    
    // Test cJSON_Version - this doesn't take parameters
    const char* version = cJSON_Version();
    if (version != NULL) {
        // Basic check to ensure version string exists
        (void)strlen(version); // Use result to prevent compiler warning
    }
    
    // Test cJSON_Minify
    cJSON_Minify(minify_input);
    
    // Test cJSON_ParseWithLengthOpts with different options
    const char* parse_end = NULL;
    
    // Parse with null termination required
    cJSON* parsed_json1 = cJSON_ParseWithLengthOpts(
        input_str, 
        size, 
        &parse_end, 
        1 // require_null_terminated = true
    );
    
    // Check for parsing errors
    const char* error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL && parse_end != NULL) {
        // Use the error pointer - just ensure it's valid
        (void)(*error_ptr); // Use result to prevent compiler warning
    }
    
    // If parsing was successful, test IsInvalid and IsRaw
    if (parsed_json1 != NULL) {
        // Test cJSON_IsInvalid
        cJSON_bool is_invalid1 = cJSON_IsInvalid(parsed_json1);
        
        // Test cJSON_IsRaw
        cJSON_bool is_raw1 = cJSON_IsRaw(parsed_json1);
        
        // Recursively check children if any
        cJSON* child = parsed_json1->child;
        while (child != NULL) {
            cJSON_IsInvalid(child);
            cJSON_IsRaw(child);
            child = child->next;
        }
        
        // Clean up
        cJSON_Delete(parsed_json1);
    }
    
    // Parse with null termination not required
    cJSON* parsed_json2 = cJSON_ParseWithLengthOpts(
        input_str, 
        size, 
        &parse_end, 
        0 // require_null_terminated = false
    );
    
    // Check for parsing errors again
    error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL && parse_end != NULL) {
        (void)(*error_ptr); // Use result to prevent compiler warning
    }
    
    // If parsing was successful, test IsInvalid and IsRaw
    if (parsed_json2 != NULL) {
        // Test cJSON_IsInvalid
        cJSON_bool is_invalid2 = cJSON_IsInvalid(parsed_json2);
        
        // Test cJSON_IsRaw
        cJSON_bool is_raw2 = cJSON_IsRaw(parsed_json2);
        
        // Recursively check children if any
        cJSON* child = parsed_json2->child;
        while (child != NULL) {
            cJSON_IsInvalid(child);
            cJSON_IsRaw(child);
            child = child->next;
        }
        
        // Clean up
        cJSON_Delete(parsed_json2);
    }
    
    // Free allocated memory
    free(input_str);
    free(minify_input);
    
    return 0;
}
