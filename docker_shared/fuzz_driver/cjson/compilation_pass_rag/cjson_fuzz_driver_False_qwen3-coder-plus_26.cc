#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON APIs: cJSON_DeleteItemFromObject, cJSON_IsObject, 
// cJSON_DeleteItemFromArray, cJSON_CreateObject, cJSON_DetachItemFromObject, cJSON_GetObjectItem

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to work with
    if (size < 10) {
        return 0;
    }

    // Create a copy of the input data to avoid modifying the original
    uint8_t* input_copy = (uint8_t*)malloc(size);
    if (!input_copy) {
        return 0;
    }
    memcpy(input_copy, data, size);

    // Initialize variables
    cJSON* root_obj = NULL;
    cJSON* array_obj = NULL;
    char* key_name = NULL;
    char* value_str = NULL;

    // Create a root JSON object
    root_obj = cJSON_CreateObject();
    if (!root_obj) {
        free(input_copy);
        return 0;
    }

    // Test cJSON_IsObject functionality
    if (!cJSON_IsObject(root_obj)) {
        cJSON_Delete(root_obj);
        free(input_copy);
        return 0;
    }

    // Extract a key name from input - use first few bytes as key name
    size_t key_len = (size > 10) ? 10 : size;
    key_name = (char*)malloc(key_len + 1);
    if (!key_name) {
        cJSON_Delete(root_obj);
        free(input_copy);
        return 0;
    }

    // Copy and null-terminate the key name
    memcpy(key_name, input_copy, key_len - 1);
    key_name[key_len - 1] = '\0';

    // Make sure key_name contains only printable characters
    for (size_t i = 0; i < key_len - 1; i++) {
        if (key_name[i] < 32 || key_name[i] > 126) {
            key_name[i] = 'A' + (i % 26);  // Replace with safe character
        }
    }

    // Create a string value from remaining data
    size_t value_start = key_len;
    size_t value_size = size - value_start;
    
    if (value_size > 0) {
        value_str = (char*)malloc(value_size + 1);
        if (value_str) {
            memcpy(value_str, input_copy + value_start, value_size);
            value_str[value_size] = '\0';
            
            // Make sure value_str contains only printable characters
            for (size_t i = 0; i < value_size; i++) {
                if (value_str[i] < 32 || value_str[i] > 126) {
                    value_str[i] = 'a' + (i % 26);  // Replace with safe character
                }
            }
            
            // Add the string value to the root object
            cJSON_AddStringToObject(root_obj, key_name, value_str);
        }
    }

    // Test cJSON_GetObjectItem - retrieve the added item
    cJSON* retrieved_item = cJSON_GetObjectItem((const cJSON*)root_obj, key_name);
    if (retrieved_item != NULL) {
        // Verify that we can access the item's value
        if (cJSON_IsString(retrieved_item)) {
            // Successfully retrieved the item
        }
    }

    // Create an array to test array-related functions
    array_obj = cJSON_CreateArray();
    if (array_obj) {
        // Add some items to the array
        cJSON_AddStringToObject(array_obj, "item0", "first");
        cJSON_AddNumberToObject(array_obj, "item1", 42);
        
        // Test cJSON_DeleteItemFromArray - try to remove an item if array has items
        if (cJSON_GetArraySize(array_obj) > 0) {
            cJSON_DeleteItemFromArray(array_obj, 0);
        }
        
        // Clean up array
        cJSON_Delete(array_obj);
    }

    // Test cJSON_DetachItemFromObject - detach the item by key
    cJSON* detached_item = cJSON_DetachItemFromObject(root_obj, key_name);
    if (detached_item) {
        // Item was successfully detached, now delete it
        cJSON_Delete(detached_item);
    } else {
        // If detach failed, try deleting directly using DeleteItemFromObject
        // Add the item back first so we have something to delete
        if (value_str) {
            cJSON_AddStringToObject(root_obj, key_name, value_str);
        }
        cJSON_DeleteItemFromObject(root_obj, key_name);
    }

    // Final verification that root_obj is still an object
    if (cJSON_IsObject(root_obj)) {
        // Root object is still valid
    }

    // Clean up
    if (root_obj) {
        cJSON_Delete(root_obj);
    }
    if (key_name) {
        free(key_name);
    }
    if (value_str) {
        free(value_str);
    }
    free(input_copy);

    return 0;
}
