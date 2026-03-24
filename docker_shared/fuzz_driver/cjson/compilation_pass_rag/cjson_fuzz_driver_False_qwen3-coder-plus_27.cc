#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON array operations
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Create a new cJSON array
    cJSON *array = cJSON_CreateArray();
    if (array == NULL) {
        return 0;
    }

    // Parse input data to determine operations
    size_t offset = 0;
    
    // Try to add some items to the array based on input data
    while (offset + sizeof(int) <= size) {
        // Create a simple integer item based on input data
        int value = *(int*)(data + offset);
        cJSON *item = cJSON_CreateNumber(value);
        
        if (item != NULL) {
            // Add the item to the array
            cJSON_AddItemToArray(array, item);
        }
        
        offset += sizeof(int);
        if (offset >= size) break;
    }
    
    // Test cJSON_GetArraySize
    int array_size = cJSON_GetArraySize(array);
    
    // Perform various array operations based on remaining input data
    if (offset + sizeof(int) * 2 <= size && array_size > 0) {
        // Get indices from input data
        int index1 = *(int*)(data + offset);
        offset += sizeof(int);
        int index2 = *(int*)(data + offset);
        offset += sizeof(int);
        
        // Normalize indices to valid range
        if (array_size > 0) {
            index1 = abs(index1) % array_size;
            if (offset + sizeof(int) <= size) {
                index2 = abs(index2) % array_size;
            } else {
                index2 = index1; // fallback if not enough data
            }
            
            // Test cJSON_GetArrayItem
            cJSON *retrieved_item1 = cJSON_GetArrayItem(array, index1);
            cJSON *retrieved_item2 = cJSON_GetArrayItem(array, index2);
            
            // Test creating a new item and adding it to the array
            if (retrieved_item1 != NULL && retrieved_item2 != NULL) {
                int sum_value = retrieved_item1->valueint + retrieved_item2->valueint;
                cJSON *new_item = cJSON_CreateNumber(sum_value);
                
                if (new_item != NULL) {
                    cJSON_AddItemToArray(array, new_item);
                }
            }
        }
    }
    
    // Perform deletion operations if possible
    array_size = cJSON_GetArraySize(array);
    if (array_size > 0 && offset + sizeof(int) <= size) {
        int del_index = abs(*(int*)(data + offset)) % array_size;
        
        // Test cJSON_DetachItemFromArray
        cJSON *detached_item = cJSON_DetachItemFromArray(array, del_index);
        if (detached_item != NULL) {
            // Reattach the item or delete it
            if (offset + sizeof(int)*2 <= size && (*(int*)(data + offset + sizeof(int))) % 2 == 0) {
                // Reattach the item back to the array
                cJSON_AddItemToArray(array, detached_item);
            } else {
                // Delete the detached item
                cJSON_Delete(detached_item);
            }
        }
    }
    
    // Perform another deletion operation using cJSON_DeleteItemFromArray
    array_size = cJSON_GetArraySize(array);
    if (array_size > 0 && offset + sizeof(int) <= size) {
        int del_index2 = abs(*(int*)(data + offset)) % array_size;
        cJSON_DeleteItemFromArray(array, del_index2);
    }
    
    // Final validation - check array size again
    int final_size = cJSON_GetArraySize(array);
    
    // Additional random operations based on input data
    if (final_size > 0 && offset + sizeof(int) <= size) {
        int access_index = abs(*(int*)(data + offset)) % final_size;
        cJSON *temp_item = cJSON_GetArrayItem(array, access_index);
        if (temp_item != NULL) {
            // Access the item's value to trigger more code paths
            double val = temp_item->valuedouble;
            val = val; // Suppress unused variable warning
        }
    }
    
    // Clean up: delete the entire array and all its contents
    cJSON_Delete(array);
    
    return 0;
}
