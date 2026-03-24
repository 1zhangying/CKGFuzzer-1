#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON APIs: cJSON_DeleteItemFromObject, cJSON_ReplaceItemInObject,
// cJSON_IsObject, cJSON_HasObjectItem, cJSON_GetObjectItemCaseSensitive, cJSON_GetObjectItem

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to work with
    if (size < 10) {
        return 0;
    }

    // Create a copy of the input data to work with
    char* input_data = (char*)malloc(size + 1);
    if (!input_data) {
        return 0;
    }
    
    memcpy(input_data, data, size);
    input_data[size] = '\0'; // Null terminate for string operations

    cJSON* root = NULL;
    cJSON* replacement_item = NULL;
    char* key_to_use = NULL;
    char* case_sensitive_key = NULL;

    // Attempt to parse the input as JSON
    root = cJSON_Parse(input_data);
    if (!root) {
        // If parsing fails, try creating a simple object instead
        root = cJSON_CreateObject();
        if (!root) {
            free(input_data);
            return 0;
        }
        
        // Add some default items to work with
        cJSON_AddStringToObject(root, "key1", "value1");
        cJSON_AddNumberToObject(root, "key2", 42);
        cJSON_AddBoolToObject(root, "key3", 1);
    }

    // Verify that the parsed/crated item is indeed an object
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        free(input_data);
        return 0;
    }

    // Determine a key to use based on input data
    size_t key_len = (size > 10) ? 10 : size / 2;
    if (key_len == 0) key_len = 1;
    
    key_to_use = (char*)malloc(key_len + 1);
    if (key_to_use) {
        memcpy(key_to_use, input_data, key_len);
        key_to_use[key_len] = '\0';
        
        // Try adding this key to the object if it doesn't exist
        if (!cJSON_HasObjectItem(root, key_to_use)) {
            cJSON_AddStringToObject(root, key_to_use, "default_value");
        }
    }

    // Test cJSON_HasObjectItem
    int has_item = cJSON_HasObjectItem(root, "key1");
    has_item = cJSON_HasObjectItem(root, "nonexistent_key");

    // Test cJSON_GetObjectItem
    cJSON* retrieved_item = cJSON_GetObjectItem(root, "key1");
    if (retrieved_item && cJSON_IsString(retrieved_item)) {
        // Successfully retrieved item
    }

    // Test cJSON_GetObjectItemCaseSensitive
    cJSON* case_retrieved_item = cJSON_GetObjectItemCaseSensitive(root, "key1");
    if (case_retrieved_item && cJSON_IsString(case_retrieved_item)) {
        // Successfully retrieved item with case-sensitive search
    }

    // Create a replacement item
    replacement_item = cJSON_CreateString("replacement_value");
    if (replacement_item && key_to_use) {
        // Test cJSON_ReplaceItemInObject
        int replace_result = cJSON_ReplaceItemInObject(root, key_to_use, replacement_item);
        if (!replace_result) {
            // If replacement failed, clean up the replacement item
            cJSON_Delete(replacement_item);
            replacement_item = NULL; // Set to NULL so we don't double-free
        } else {
            // If replacement succeeded, the old item was deleted and replacement_item is now part of the object
            replacement_item = NULL; // Don't delete it since it's now part of the object
        }
    }

    // Test cJSON_DeleteItemFromObject
    if (key_to_use && cJSON_HasObjectItem(root, key_to_use)) {
        cJSON_DeleteItemFromObject(root, key_to_use);
    }

    // Perform additional operations with different keys
    if (size > 20) {
        case_sensitive_key = (char*)malloc(11);
        if (case_sensitive_key) {
            memcpy(case_sensitive_key, input_data + 10, 10);
            case_sensitive_key[10] = '\0';
            
            // Add the case sensitive key to the object if it doesn't exist
            if (!cJSON_HasObjectItem(root, case_sensitive_key)) {
                cJSON_AddNumberToObject(root, case_sensitive_key, 123);
            }
            
            // Test case-sensitive retrieval
            cJSON* cs_item = cJSON_GetObjectItemCaseSensitive(root, case_sensitive_key);
            if (cs_item) {
                // Successfully retrieved with case-sensitive match
            }
            
            // Delete the case-sensitive key item
            cJSON_DeleteItemFromObject(root, case_sensitive_key);
        }
    }

    // Clean up
    if (root) {
        cJSON_Delete(root);
    }
    if (input_data) {
        free(input_data);
    }
    if (key_to_use) {
        free(key_to_use);
    }
    if (case_sensitive_key) {
        free(case_sensitive_key);
    }

    return 0;
}
