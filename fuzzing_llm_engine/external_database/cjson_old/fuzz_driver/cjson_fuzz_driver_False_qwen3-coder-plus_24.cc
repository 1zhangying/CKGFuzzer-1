#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON manipulation APIs
// This fuzz driver tests the following APIs:
// - cJSON_DeleteItemFromObject
// - cJSON_Delete
// - cJSON_DeleteItemFromArray
// - cJSON_ReplaceItemInArray
// - cJSON_DetachItemFromObject
// - cJSON_DetachItemFromArray

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to work with
    if (size < 10) {
        return 0;
    }

    // Create a copy of the input data to work with
    char* input_copy = (char*)malloc(size + 1);
    if (!input_copy) {
        return 0;
    }
    
    memcpy(input_copy, data, size);
    input_copy[size] = '\0'; // Null-terminate for string operations

    // Parse the input as JSON
    cJSON* root = cJSON_Parse(input_copy);
    if (!root) {
        free(input_copy);
        return 0;
    }

    // Make a copy for various operations
    cJSON* json_copy = cJSON_Parse(input_copy);
    if (!json_copy) {
        cJSON_Delete(root);
        free(input_copy);
        return 0;
    }

    // Prepare some data for operations based on fuzz input
    size_t offset = 0;
    
    // Extract parameters from fuzz input for various operations
    if (size >= 15) {
        // Use part of the input data as a key string for object operations
        char key[10];
        size_t key_len = (data[offset] % 5) + 1; // Limit key length to 1-5 chars
        offset++;
        
        for (size_t i = 0; i < key_len && (offset + i) < size; i++) {
            key[i] = (char)data[offset + i] % 94 + 32; // Printable ASCII characters
        }
        key[key_len] = '\0';
        offset += key_len;

        // Use next byte as an index for array operations
        int array_index = 0;
        if (offset < size) {
            array_index = (int)data[offset] % 10; // Limit to 0-9
            offset++;
        }

        // Test cJSON_DetachItemFromObject
        cJSON* detached_obj = cJSON_DetachItemFromObject(json_copy, key);
        if (detached_obj) {
            // Test cJSON_Delete on the detached item
            cJSON_Delete(detached_obj);
        }

        // Reparse to get fresh object
        cJSON_Delete(json_copy);
        json_copy = cJSON_Parse(input_copy);
        if (!json_copy) {
            cJSON_Delete(root);
            free(input_copy);
            return 0;
        }

        // Test cJSON_DeleteItemFromObject
        cJSON_DeleteItemFromObject(json_copy, key);

        // Reparse again
        cJSON_Delete(json_copy);
        json_copy = cJSON_Parse(input_copy);
        if (!json_copy) {
            cJSON_Delete(root);
            free(input_copy);
            return 0;
        }

        // Test cJSON_DetachItemFromArray
        cJSON* detached_item = cJSON_DetachItemFromArray(json_copy, array_index);
        if (detached_item) {
            // Test cJSON_Delete on the detached item
            cJSON_Delete(detached_item);
        }

        // Reparse again
        cJSON_Delete(json_copy);
        json_copy = cJSON_Parse(input_copy);
        if (!json_copy) {
            cJSON_Delete(root);
            free(input_copy);
            return 0;
        }

        // Test cJSON_DeleteItemFromArray
        cJSON_DeleteItemFromArray(json_copy, array_index);

        // Reparse again
        cJSON_Delete(json_copy);
        json_copy = cJSON_Parse(input_copy);
        if (!json_copy) {
            cJSON_Delete(root);
            free(input_copy);
            return 0;
        }

        // Create a new item for replacement
        cJSON* new_item = cJSON_CreateString("replacement");
        if (new_item) {
            // Test cJSON_ReplaceItemInArray
            cJSON_bool replace_result = cJSON_ReplaceItemInArray(json_copy, array_index, new_item);
            // If replacement failed, we need to delete the new item ourselves
            if (!replace_result) {
                cJSON_Delete(new_item);
            }
        }

        // Clean up json_copy
        cJSON_Delete(json_copy);
    }

    // Additional tests with different approaches
    // Try to create a simple JSON object/array for more testing
    cJSON* test_obj = cJSON_CreateObject();
    if (test_obj) {
        // Add some items to the test object
        cJSON_AddStringToObject(test_obj, "key1", "value1");
        cJSON_AddNumberToObject(test_obj, "key2", 42);
        
        // Add an array
        cJSON* arr = cJSON_CreateArray();
        cJSON_AddItemToArray(arr, cJSON_CreateString("item1"));
        cJSON_AddItemToArray(arr, cJSON_CreateNumber(123));
        cJSON_AddItemToObject(test_obj, "array", arr);
        
        // Test operations on this constructed object
        char alt_key[5];
        size_t alt_key_len = (size > 0 ? data[0] : 1) % 4 + 1;
        for (size_t i = 0; i < alt_key_len; i++) {
            alt_key[i] = 'a' + (i % 26);
        }
        alt_key[alt_key_len] = '\0';
        
        // Try to detach non-existent key (should return NULL)
        cJSON* detached = cJSON_DetachItemFromObject(test_obj, alt_key);
        if (detached) {
            cJSON_Delete(detached);
        }
        
        // Try to detach existing key
        detached = cJSON_DetachItemFromObject(test_obj, "key1");
        if (detached) {
            cJSON_Delete(detached);
        }
        
        // Try to delete array item by index
        cJSON* array_item = cJSON_GetObjectItem(test_obj, "array");
        if (array_item && cJSON_IsArray(array_item)) {
            cJSON_DeleteItemFromArray(array_item, 0);
        }
        
        // Clean up test object
        cJSON_Delete(test_obj);
    }

    // Final cleanup
    cJSON_Delete(root);
    free(input_copy);

    return 0;
}
