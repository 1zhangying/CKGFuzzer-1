#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON array manipulation functions
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cJSON *root = NULL;
    cJSON *item = NULL;
    cJSON *new_item = NULL;
    
    // Early exit if size is too small to process
    if (size < 4) {
        return 0;
    }
    
    // Parse the input data to create a root JSON array
    // Use the first part of the data as a JSON string to parse
    size_t json_size = size > 100 ? 100 : size; // Limit JSON string size to prevent excessive memory usage
    char *json_str = (char*)malloc(json_size + 1);
    if (!json_str) {
        return 0;
    }
    
    memcpy(json_str, data, json_size);
    json_str[json_size] = '\0';
    
    // Try to parse the string as JSON
    root = cJSON_Parse(json_str);
    
    // If parsing fails or result is not an array, create an empty array
    if (!root || !cJSON_IsArray(root)) {
        if (root) {
            cJSON_Delete(root);
        }
        root = cJSON_CreateArray();
        if (!root) {
            free(json_str);
            return 0;
        }
        
        // Add some initial items to work with
        cJSON *temp_item1 = cJSON_CreateString("initial_item_1");
        cJSON *temp_item2 = cJSON_CreateNumber(42);
        cJSON *temp_item3 = cJSON_CreateBool(true);
        
        if (temp_item1) cJSON_AddItemToArray(root, temp_item1);
        if (temp_item2) cJSON_AddItemToArray(root, temp_item2);
        if (temp_item3) cJSON_AddItemToArray(root, temp_item3);
    }
    
    // Extract additional parameters from remaining data for operations
    size_t offset = json_size;
    if (offset + 12 <= size) { // Need at least 12 bytes for 3 integers
        int index1 = *(uint32_t*)(data + offset) % 100; // Keep index reasonable
        int index2 = *(uint32_t*)(data + offset + 4) % 100;
        int operation_type = *(uint32_t*)(data + offset + 8) % 6; // 6 different operations
        
        // Make sure indices are not negative
        if (index1 < 0) index1 = -index1;
        if (index2 < 0) index2 = -index2;
        
        // Perform various array operations based on operation_type
        switch (operation_type) {
            case 0: {
                // Test cJSON_GetArrayItem
                cJSON *retrieved_item = cJSON_GetArrayItem(root, index1);
                if (retrieved_item) {
                    // Just access the item to make sure it works
                    (void)cJSON_Print(retrieved_item); // Use result to avoid warnings
                }
                break;
            }
            
            case 1: {
                // Test cJSON_AddItemToArray
                item = cJSON_CreateString("added_item");
                if (item) {
                    cJSON_AddItemToArray(root, item);
                }
                break;
            }
            
            case 2: {
                // Test cJSON_DeleteItemFromArray
                // Only delete if array has items
                int current_size = cJSON_GetArraySize(root);
                if (current_size > 0 && index1 < current_size) {
                    cJSON_DeleteItemFromArray(root, index1);
                }
                break;
            }
            
            case 3: {
                // Test cJSON_GetArraySize
                int array_size = cJSON_GetArraySize(root);
                // Use the size value to avoid compiler warning
                (void)array_size;
                break;
            }
            
            case 4: {
                // Test cJSON_ReplaceItemInArray
                int current_size = cJSON_GetArraySize(root);
                if (current_size > 0 && index1 < current_size) {
                    new_item = cJSON_CreateString("replaced_item");
                    if (new_item) {
                        cJSON_ReplaceItemInArray(root, index1, new_item);
                    }
                }
                break;
            }
            
            case 5: {
                // Test cJSON_DetachItemFromArray
                int current_size = cJSON_GetArraySize(root);
                if (current_size > 0 && index1 < current_size) {
                    cJSON *detached_item = cJSON_DetachItemFromArray(root, index1);
                    if (detached_item) {
                        // Free the detached item since we're not adding it back
                        cJSON_Delete(detached_item);
                    }
                }
                break;
            }
        }
    } else {
        // If we don't have enough data for parameters, just run basic operations
        // Get array size
        int array_size = cJSON_GetArraySize(root);
        
        // Try to get an item if array is not empty
        if (array_size > 0) {
            cJSON *item = cJSON_GetArrayItem(root, 0);
            (void)item; // Use to avoid warning
            
            // Try to detach an item
            cJSON *detached = cJSON_DetachItemFromArray(root, 0);
            if (detached) {
                // Add it back to keep the array intact
                cJSON_AddItemToArray(root, detached);
            }
        }
        
        // Add a new item
        cJSON *new_item = cJSON_CreateNumber(123);
        if (new_item) {
            cJSON_AddItemToArray(root, new_item);
        }
    }
    
    // Perform a few more operations regardless of the main operation path
    int final_size = cJSON_GetArraySize(root);
    
    // Try to replace an item if possible
    if (final_size > 0) {
        cJSON *replacement = cJSON_CreateNull();
        if (replacement) {
            cJSON_ReplaceItemInArray(root, 0, replacement);
        }
    }
    
    // Clean up
    if (root) {
        cJSON_Delete(root);
    }
    
    free(json_str);
    
    return 0;
}
