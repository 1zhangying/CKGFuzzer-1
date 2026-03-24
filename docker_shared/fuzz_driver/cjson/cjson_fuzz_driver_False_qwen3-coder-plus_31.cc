#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON array manipulation APIs
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 1) {
        return 0;
    }
    
    // Create a copy of input data to avoid modifying original
    char* input_copy = (char*)malloc(size + 1);
    if (!input_copy) {
        return 0;
    }
    memcpy(input_copy, data, size);
    input_copy[size] = '\0'; // Null terminate for string operations
    
    // Parse input as JSON
    cJSON* root = cJSON_Parse(input_copy);
    if (!root) {
        free(input_copy);
        return 0;
    }
    
    // Test cJSON_CreateArray - Create a new array
    cJSON* test_array = cJSON_CreateArray();
    if (!test_array) {
        cJSON_Delete(root);
        free(input_copy);
        return 0;
    }
    
    // If root is an array, perform array operations
    if (cJSON_IsArray(root)) {
        // Test cJSON_GetArraySize
        int array_size = cJSON_GetArraySize(root);
        
        // Test cJSON_GetArrayItem for each index (if array is not empty)
        if (array_size > 0) {
            for (int i = 0; i < array_size && i < 10; i++) { // Limit iterations for performance
                cJSON* item = cJSON_GetArrayItem(root, i);
                if (item != NULL) {
                    // Add this item to our test array
                    cJSON_AddItemReferenceToArray(test_array, item);
                }
            }
        }
        
        // Test cJSON_GetArraySize on our test array
        int test_array_size = cJSON_GetArraySize(test_array);
        
        // Test cJSON_DetachItemFromArray and cJSON_DeleteItemFromArray
        for (int j = test_array_size - 1; j >= 0 && j >= test_array_size - 5; j--) { // Limit deletions
            if (j >= 0) {
                // Try to detach an item
                cJSON* detached_item = cJSON_DetachItemFromArray(test_array, j);
                if (detached_item != NULL) {
                    // Delete the detached item to free memory
                    cJSON_Delete(detached_item);
                } else {
                    // If detach failed, try delete directly
                    cJSON_DeleteItemFromArray(test_array, j);
                }
            }
        }
    }
    
    // If root is an object, test cJSON_GetObjectItem
    if (cJSON_IsObject(root)) {
        // Attempt to find some common keys in the object
        cJSON* obj_item = cJSON_GetObjectItem(root, "key");
        if (obj_item && cJSON_IsArray(obj_item)) {
            int sub_array_size = cJSON_GetArraySize(obj_item);
            for (int k = 0; k < sub_array_size && k < 5; k++) { // Limit iterations
                cJSON* sub_item = cJSON_GetArrayItem(obj_item, k);
                if (sub_item != NULL) {
                    // Add reference to our test array
                    cJSON_AddItemReferenceToArray(test_array, sub_item);
                }
            }
        }
        
        // Also try with other possible keys
        obj_item = cJSON_GetObjectItem(root, "array");
        if (obj_item && cJSON_IsArray(obj_item)) {
            int sub_array_size = cJSON_GetArraySize(obj_item);
            for (int k = 0; k < sub_array_size && k < 5; k++) {
                cJSON* sub_item = cJSON_GetArrayItem(obj_item, k);
                if (sub_item != NULL) {
                    // Add reference to our test array
                    cJSON_AddItemReferenceToArray(test_array, sub_item);
                }
            }
        }
    }
    
    // Clean up all created and modified objects
    cJSON_Delete(test_array);
    cJSON_Delete(root);
    free(input_copy);
    
    return 0;
}
