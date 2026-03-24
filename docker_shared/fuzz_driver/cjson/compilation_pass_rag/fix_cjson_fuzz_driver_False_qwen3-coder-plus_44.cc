#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation to test cJSON APIs
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a null-terminated string from the input data
    if (size == 0) {
        return 0;
    }
    
    // Allocate memory for the input string and copy the data
    char* input_str = (char*)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    
    memcpy(input_str, data, size);
    input_str[size] = '\0';
    
    cJSON* parsed_json = NULL;
    cJSON* obj1 = NULL;
    cJSON* obj2 = NULL;
    cJSON* value1 = NULL;
    cJSON* value2 = NULL;
    cJSON* retrieved_item = NULL;
    // Declare variables that were causing goto issues earlier
    cJSON* retrieved_test = NULL;
    cJSON* nested_retrieved = NULL;
    cJSON* deleted_item = NULL;
    
    // Test cJSON_Parse - Parse the input string as JSON
    parsed_json = cJSON_Parse(input_str);
    
    // Test cJSON_IsObject - Check if the parsed JSON is an object
    if (parsed_json && cJSON_IsObject(parsed_json)) {
        // Work with the parsed object
        // Get an item from the object if possible
        retrieved_item = cJSON_GetObjectItem(parsed_json, "test_key");
        if (retrieved_item) {
            // Item found with "test_key"
        } else {
            // Item not found, continue anyway
        }
        
        // Try to delete an item from the object
        cJSON_DeleteItemFromObject(parsed_json, "delete_me");
    }
    
    // Test cJSON_CreateObject - Create a new JSON object
    obj1 = cJSON_CreateObject();
    if (!obj1) {
        goto cleanup;
    }
    
    // Create another object
    obj2 = cJSON_CreateObject();
    if (!obj2) {
        goto cleanup;
    }
    
    // Add the second object as a child to the first one
    if (!cJSON_AddItemToObject(obj1, "nested_obj", obj2)) {
        // Failed to add item, clean up obj2 manually
        cJSON_Delete(obj2);
        obj2 = NULL;
    }
    
    // Create a string value to add to the object
    value1 = cJSON_CreateString("test_value");
    if (value1) {
        if (!cJSON_AddItemToObject(obj1, "test_key", value1)) {
            // Failed to add, clean up manually
            cJSON_Delete(value1);
            value1 = NULL;
        }
    }
    
    // Create a number value to add to the object
    value2 = cJSON_CreateNumber(42);
    if (value2) {
        if (!cJSON_AddItemToObject(obj1, "number_key", value2)) {
            // Failed to add, clean up manually
            cJSON_Delete(value2);
            value2 = NULL;
        }
    }
    
    // Test cJSON_GetObjectItem - retrieve items we just added
    retrieved_test = cJSON_GetObjectItem(obj1, "test_key");
    if (retrieved_test && cJSON_IsObject(retrieved_test)) {
        // This shouldn't happen since we added a string, but test anyway
    }
    
    // Retrieve the nested object
    nested_retrieved = cJSON_GetObjectItem(obj1, "nested_obj");
    if (nested_retrieved && cJSON_IsObject(nested_retrieved)) {
        // Successfully retrieved the nested object
    }
    
    // Test cJSON_DeleteItemFromObject - delete an item
    cJSON_DeleteItemFromObject(obj1, "test_key");
    
    // Try to get the deleted item (should return NULL)
    deleted_item = cJSON_GetObjectItem(obj1, "test_key");
    if (deleted_item) {
        // Item still exists (unexpected)
    }
    
    // Clean up all allocated resources
cleanup:
    if (parsed_json) {
        cJSON_Delete(parsed_json);
    }
    
    // Note: obj2 might have been freed when added to obj1, so don't double-free
    // Only delete obj1 which owns all sub-items
    if (obj1) {
        cJSON_Delete(obj1);
    }
    
    // Free the input string
    free(input_str);
    
    return 0;
}
