#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON object manipulation APIs
// This fuzz driver tests various cJSON object operations including:
// - Adding items to objects
// - Getting items from objects (case sensitive and insensitive)
// - Replacing items in objects
// - Detaching items from objects
// - Deleting items from objects

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a copy of the input data to work with
    char* input_copy = (char*)malloc(size + 1);
    if (!input_copy) {
        return 0;
    }
    memcpy(input_copy, data, size);
    input_copy[size] = '\0';

    // Parse the input as JSON
    cJSON* root = cJSON_Parse(input_copy);
    
    // If parsing fails, try to create an empty object to continue testing
    if (!root) {
        root = cJSON_CreateObject();
        if (!root) {
            free(input_copy);
            return 0;
        }
    }

    // We'll use part of the input data to extract keys and values for our operations
    size_t offset = 0;
    
    // Extract a key name for operations (first 10 bytes max, null-terminated)
    const size_t max_key_len = 10;
    char key[max_key_len + 1];
    size_t key_len = (size > offset) ? size - offset : 0;
    if (key_len > max_key_len) {
        key_len = max_key_len;
    }
    
    if (key_len > 0) {
        memcpy(key, input_copy + offset, key_len);
        key[key_len] = '\0';
        offset += key_len;
    } else {
        strcpy(key, "default");  // Default key if no data available
    }

    // Perform cJSON operations
    
    // Test cJSON_GetObjectItem (case-insensitive)
    cJSON* item1 = cJSON_GetObjectItem(root, key);
    
    // Test cJSON_GetObjectItemCaseSensitive
    cJSON* item2 = cJSON_GetObjectItemCaseSensitive(root, key);
    
    // Create a new item to add or replace
    cJSON* new_item = cJSON_CreateString("fuzz_test_value");
    if (new_item) {
        // Test cJSON_AddItemToObject
        int add_result = cJSON_AddItemToObject(root, "test_key", new_item);
        
        // If add failed, we need to clean up the new_item ourselves
        if (!add_result) {
            cJSON_Delete(new_item);
        }
    }
    
    // Try to replace an item in the object
    cJSON* replacement_item = cJSON_CreateNumber(42);
    if (replacement_item) {
        int replace_result = cJSON_ReplaceItemInObject(root, "test_key", replacement_item);
        
        // If replace failed, we need to clean up the replacement_item ourselves
        if (!replace_result) {
            cJSON_Delete(replacement_item);
        }
    }
    
    // Try to detach an item from the object
    cJSON* detached_item = cJSON_DetachItemFromObject(root, "test_key");
    if (detached_item) {
        // If successfully detached, we're responsible for deleting it
        cJSON_Delete(detached_item);
    }
    
    // Try to delete an item from the object
    // Note: This will try to detach and delete the item with the given key
    cJSON_DeleteItemFromObject(root, key);
    
    // Clean up the root object
    cJSON_Delete(root);
    
    // Free the input copy
    free(input_copy);
    
    return 0;
}
