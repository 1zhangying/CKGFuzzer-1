#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests the following APIs:
// - cJSON_AddStringToObject
// - cJSON_IsString
// - cJSON_CreateObject
// - cJSON_Delete
// - cJSON_Parse
// - cJSON_GetObjectItem

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 10) {
        return 0;
    }

    // Create a copy of the input data to work with, null-terminated for string operations
    char* input_str = (char*)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Parse the input as JSON
    cJSON* parsed_json = cJSON_Parse(input_str);
    
    // Test cJSON_CreateObject
    cJSON* obj = cJSON_CreateObject();
    if (!obj) {
        free(input_str);
        if (parsed_json) {
            cJSON_Delete(parsed_json);
        }
        return 0;
    }

    // If parsing succeeded, perform operations on the parsed JSON
    if (parsed_json) {
        // Test cJSON_GetObjectItem - try to get some common keys if this is an object
        if (cJSON_IsObject(parsed_json)) {
            cJSON* item1 = cJSON_GetObjectItem(parsed_json, "key1");
            if (item1 && cJSON_IsString(item1)) {
                // Do nothing, just verifying functionality
            }
            
            cJSON* item2 = cJSON_GetObjectItem(parsed_json, "name");
            if (item2 && cJSON_IsString(item2)) {
                // Do nothing, just verifying functionality
            }
        }
        
        // Clean up parsed JSON
        cJSON_Delete(parsed_json);
    }

    // Test cJSON_AddStringToObject - add several string items to our object
    // Use part of the input data as key names and values
    if (size >= 20) {
        // Create substrings from input for key/value pairs
        char key1[10];
        char val1[10];
        
        size_t key_len = (size > 5) ? 5 : size;
        size_t val_len = (size > 10) ? 5 : (size > 5 ? size - 5 : 0);
        
        memcpy(key1, input_str, key_len);
        key1[key_len] = '\0';
        
        if (val_len > 0) {
            memcpy(val1, input_str + key_len, val_len);
            val1[val_len] = '\0';
            
            cJSON* added_item = cJSON_AddStringToObject(obj, key1, val1);
            if (added_item) {
                // Verify that the added item is indeed a string
                if (cJSON_IsString(added_item)) {
                    // Do nothing, just verifying functionality
                }
            }
        }
    }
    
    // Add a fixed key-value pair to ensure we have at least one item
    cJSON* fixed_item = cJSON_AddStringToObject(obj, "fixed_key", "fixed_value");
    if (fixed_item) {
        // Verify that the added item is indeed a string
        if (cJSON_IsString(fixed_item)) {
            // Do nothing, just verifying functionality
        }
    }
    
    // Try to retrieve the item we just added
    cJSON* retrieved_item = cJSON_GetObjectItem(obj, "fixed_key");
    if (retrieved_item) {
        if (cJSON_IsString(retrieved_item)) {
            // Do nothing, just verifying functionality
        }
    }
    
    // Perform additional operations based on input size
    if (size > 30) {
        char key2[10];
        char val2[10];
        
        size_t offset = 20;
        size_t key2_len = (size - offset > 5) ? 5 : (size - offset);
        size_t val2_len = (size - offset - key2_len > 5) ? 5 : (size - offset - key2_len);
        
        if (key2_len > 0 && val2_len > 0) {
            memcpy(key2, input_str + offset, key2_len);
            key2[key2_len] = '\0';
            
            memcpy(val2, input_str + offset + key2_len, val2_len);
            val2[val2_len] = '\0';
            
            cJSON_AddStringToObject(obj, key2, val2);
        }
    }
    
    // Clean up the created object
    cJSON_Delete(obj);
    
    // Free the input string
    free(input_str);
    
    return 0;
}
