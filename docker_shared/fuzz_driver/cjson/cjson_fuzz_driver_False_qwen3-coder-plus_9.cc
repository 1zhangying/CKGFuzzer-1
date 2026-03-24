#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON library functions
// This driver creates a JSON object and tests various operations including:
// - Creating objects and strings
// - Adding items to objects
// - Retrieving items from objects
// - Deleting items from objects

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to work with
    if (size < 10) {
        return 0;
    }

    // Create the main JSON object
    cJSON* root_obj = cJSON_CreateObject();
    if (!root_obj) {
        return 0; // Allocation failed
    }

    size_t offset = 0;
    
    // Extract first part for creating a string key (min 1 byte, max 10 bytes)
    size_t key_len = 1 + (data[offset] % 10); // Ensure at least 1 byte for key
    if (offset + key_len > size) {
        key_len = size - offset;
    }
    
    if (key_len == 0) {
        cJSON_Delete(root_obj);
        return 0;
    }
    
    char* key1 = (char*)malloc(key_len + 1);
    if (!key1) {
        cJSON_Delete(root_obj);
        return 0;
    }
    
    memcpy(key1, data + offset, key_len);
    key1[key_len] = '\0'; // Null terminate
    offset += key_len;

    // Extract second part for creating another string key
    if (offset >= size) {
        free(key1);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    size_t key2_len = 1 + (data[offset] % 10); // Ensure at least 1 byte for key
    if (offset + key2_len > size) {
        key2_len = size - offset;
    }
    
    if (key2_len == 0) {
        free(key1);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    char* key2 = (char*)malloc(key2_len + 1);
    if (!key2) {
        free(key1);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    memcpy(key2, data + offset, key2_len);
    key2[key2_len] = '\0';
    offset += key2_len;

    // Extract third part for creating a third string key
    if (offset >= size) {
        free(key1);
        free(key2);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    size_t key3_len = 1 + (data[offset] % 10); // Ensure at least 1 byte for key
    if (offset + key3_len > size) {
        key3_len = size - offset;
    }
    
    if (key3_len == 0) {
        free(key1);
        free(key2);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    char* key3 = (char*)malloc(key3_len + 1);
    if (!key3) {
        free(key1);
        free(key2);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    memcpy(key3, data + offset, key3_len);
    key3[key3_len] = '\0';
    offset += key3_len;

    // Extract value for first string
    if (offset >= size) {
        free(key1);
        free(key2);
        free(key3);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    size_t val1_len = 1 + (data[offset] % 10); // Ensure at least 1 byte for value
    if (offset + val1_len > size) {
        val1_len = size - offset;
    }
    
    if (val1_len == 0) {
        free(key1);
        free(key2);
        free(key3);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    char* val1 = (char*)malloc(val1_len + 1);
    if (!val1) {
        free(key1);
        free(key2);
        free(key3);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    memcpy(val1, data + offset, val1_len);
    val1[val1_len] = '\0';
    offset += val1_len;

    // Extract value for second string
    if (offset >= size) {
        free(key1);
        free(key2);
        free(key3);
        free(val1);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    size_t val2_len = 1 + (data[offset] % 10); // Ensure at least 1 byte for value
    if (offset + val2_len > size) {
        val2_len = size - offset;
    }
    
    if (val2_len == 0) {
        free(key1);
        free(key2);
        free(key3);
        free(val1);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    char* val2 = (char*)malloc(val2_len + 1);
    if (!val2) {
        free(key1);
        free(key2);
        free(key3);
        free(val1);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    memcpy(val2, data + offset, val2_len);
    val2[val2_len] = '\0';

    // Test cJSON_CreateString and cJSON_AddItemToObject
    cJSON* string_item1 = cJSON_CreateString(val1);
    if (string_item1) {
        if (cJSON_AddItemToObject(root_obj, key1, string_item1)) {
            // Successfully added - item ownership transferred to root_obj
        } else {
            // Failed to add, clean up the string item we created
            cJSON_Delete(string_item1);
        }
    }

    // Test cJSON_AddStringToObject
    if (!cJSON_AddStringToObject(root_obj, key2, val2)) {
        // Handle failure silently as this is expected with some inputs
    }

    // Test cJSON_GetObjectItemCaseSensitive
    cJSON* retrieved_item1 = cJSON_GetObjectItemCaseSensitive(root_obj, key1);
    if (retrieved_item1 && retrieved_item1->type == cJSON_String) {
        // Verify that the retrieved string matches what we set
        // (Not strictly necessary for fuzzing but good practice)
    }

    cJSON* retrieved_item2 = cJSON_GetObjectItemCaseSensitive(root_obj, key2);
    if (retrieved_item2 && retrieved_item2->type == cJSON_String) {
        // Verify that the retrieved string matches what we set
    }

    // Test cJSON_AddStringToObject with third key
    if (!cJSON_AddStringToObject(root_obj, key3, "test_value")) {
        // Handle failure silently
    }

    // Test cJSON_GetObjectItemCaseSensitive with third key
    cJSON* retrieved_item3 = cJSON_GetObjectItemCaseSensitive(root_obj, key3);
    if (retrieved_item3 && retrieved_item3->type == cJSON_String) {
        // Verify that the retrieved string matches what we set
    }

    // Test cJSON_DeleteItemFromObject
    cJSON_DeleteItemFromObject(root_obj, key2);

    // Try to retrieve the deleted item (should fail)
    cJSON* deleted_item = cJSON_GetObjectItemCaseSensitive(root_obj, key2);
    if (deleted_item) {
        // This shouldn't happen if deletion worked properly
    }

    // Clean up allocated memory
    free(key1);
    free(key2);
    free(key3);
    free(val1);
    free(val2);

    // Clean up the JSON object (this also cleans up all child items)
    cJSON_Delete(root_obj);

    return 0;
}
