#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for cJSON library testing
// This fuzzer tests various cJSON operations including array creation, string creation,
// JSON parsing, printing with buffering, and array item addition

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to work with
    if (size < 1) {
        return 0;
    }

    // Create a copy of input data that we can safely modify
    char* input_copy = (char*)malloc(size + 1);
    if (!input_copy) {
        return 0;
    }
    
    memcpy(input_copy, data, size);
    input_copy[size] = '\0'; // Null terminate for string operations
    
    // Initialize variables for JSON operations
    cJSON* root = NULL;
    cJSON* array = NULL;
    cJSON* string_item = NULL;
    char* printed_json = NULL;
    cJSON* parsed_json = NULL;
    
    // Create a JSON array using cJSON_CreateArray
    array = cJSON_CreateArray();
    if (!array) {
        free(input_copy);
        return 0;
    }
    
    // Create a string item from part of the input data
    // Use first half of input for string creation (or full if small)
    size_t string_len = size > 0 ? size / 2 : 0;
    if (string_len == 0 && size > 0) {
        string_len = 1;  // At least one character if available
    }
    
    char* temp_str = (char*)malloc(string_len + 1);
    if (temp_str) {
        memcpy(temp_str, input_copy, string_len);
        temp_str[string_len] = '\0';
        
        string_item = cJSON_CreateString(temp_str);
        free(temp_str);
        
        if (string_item) {
            // Add the string item to the array
            cJSON_bool add_result = cJSON_AddItemToArray(array, string_item);
            // If adding fails, the string_item remains unowned and needs deletion
            if (add_result != true) {
                cJSON_Delete(string_item);
            }
        }
    }
    
    // Try to parse the original input as JSON (could be valid JSON)
    parsed_json = cJSON_Parse(input_copy);
    if (parsed_json) {
        // If parsing was successful, try to print it with buffering
        // Use the second half of the input data to determine buffer size
        int prebuffer_size = 1024; // Default buffer size
        if (size > 1) {
            // Use part of the input data to determine prebuffer size
            // Limit to reasonable range to prevent huge allocations
            prebuffer_size = 1 + (input_copy[size - 1] % 2047); 
        }
        
        printed_json = cJSON_PrintBuffered(parsed_json, prebuffer_size, 1); // Formatted print
        cJSON_Delete(parsed_json);
        parsed_json = NULL;
    } else {
        // If parsing failed, try to print our constructed array instead
        int prebuffer_size = 1024; // Default buffer size
        if (size > 1) {
            prebuffer_size = 1 + (input_copy[size - 1] % 2047); 
        }
        
        printed_json = cJSON_PrintBuffered(array, prebuffer_size, 1);
    }
    
    // Create a root object to hold both the array and possibly a parsed object
    root = cJSON_CreateArray();
    if (root) {
        // Add our original array to the root
        cJSON_AddItemToArray(root, array);
        array = NULL; // Transfer ownership to root
        
        // If we have printed JSON, try parsing it again and adding to root
        if (printed_json) {
            cJSON* reparsed = cJSON_Parse(printed_json);
            if (reparsed) {
                cJSON_AddItemToArray(root, reparsed);
            }
        }
        
        // Print the root object
        char* final_print = cJSON_PrintBuffered(root, 512, 1);
        if (final_print) {
            free(final_print);
        }
        
        // Clean up root which also cleans up contained items
        cJSON_Delete(root);
    } else {
        // If root creation failed, clean up array separately
        cJSON_Delete(array);
    }
    
    // Free the printed JSON string if it was created
    if (printed_json) {
        free(printed_json);
    }
    
    // Free the copied input
    free(input_copy);
    
    return 0;
}
