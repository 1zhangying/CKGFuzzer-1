#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON array manipulation APIs
// This fuzz driver tests the following APIs:
// - cJSON_CreateArray: Creates a new JSON array
// - cJSON_GetArraySize: Gets the size of an array
// - cJSON_GetArrayItem: Gets an item from an array at a specific index
// - cJSON_DeleteItemFromArray: Deletes an item from an array
// - cJSON_DetachItemFromArray: Detaches an item from an array
// - cJSON_Delete: Deletes a JSON object and frees its memory

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Create a JSON array
    cJSON* array = cJSON_CreateArray();
    if (array == NULL) {
        return 0; // Failed to create array, exit early
    }

    // Use part of the input data to determine how many items to add to the array
    size_t offset = 0;
    int num_items_to_add = 0;
    
    if (offset + sizeof(int) <= size) {
        num_items_to_add = *(const int*)(data + offset);
        offset += sizeof(int);
        // Limit the number of items to prevent excessive memory usage
        num_items_to_add = abs(num_items_to_add) % 20; 
    } else {
        cJSON_Delete(array);
        return 0;
    }

    // Add items to the array based on remaining input data
    for (int i = 0; i < num_items_to_add && offset < size; i++) {
        // Determine type of item to add based on available data
        cJSON* item = NULL;
        
        if (offset + sizeof(int) <= size) {
            int value = *(const int*)(data + offset);
            offset += sizeof(int);
            
            // Alternate between creating different types of items
            if ((value % 3) == 0) {
                item = cJSON_CreateNumber(value);
            } else if ((value % 3) == 1) {
                // Create a string based on input data
                size_t str_len = (abs(value) % 10) + 1; // Max 10 chars
                if (offset + str_len <= size) {
                    char* str = (char*)malloc(str_len + 1);
                    if (str != NULL) {
                        memcpy(str, data + offset, str_len);
                        str[str_len] = '\0';
                        item = cJSON_CreateString(str);
                        free(str);
                        offset += str_len;
                    }
                }
            } else {
                // Create a boolean value
                item = cJSON_CreateBool((value % 2) == 0 ? 1 : 0);
            }
        } else {
            break; // Not enough data left to create more items
        }
        
        if (item != NULL) {
            cJSON_AddItemToArray(array, item);
        }
    }

    // Test cJSON_GetArraySize
    int array_size = cJSON_GetArraySize(array);
    
    // Test cJSON_GetArrayItem with various indices
    for (int idx = 0; idx < array_size && idx < 10; idx++) { // Limit iterations
        cJSON* item = cJSON_GetArrayItem(array, idx);
        if (item != NULL) {
            // Do nothing, just verify we can retrieve the item
        }
    }

    // Use another portion of input data to determine which indices to manipulate
    while (offset + sizeof(int) <= size && cJSON_GetArraySize(array) > 0) {
        int index_to_manipulate = *(const int*)(data + offset);
        offset += sizeof(int);
        
        if (index_to_manipulate < 0) {
            index_to_manipulate = -index_to_manipulate; // Make positive
        }
        
        int current_size = cJSON_GetArraySize(array);
        if (current_size > 0) {
            int valid_index = index_to_manipulate % current_size;
            
            // Test cJSON_GetArrayItem with the calculated index
            cJSON* retrieved_item = cJSON_GetArrayItem(array, valid_index);
            
            // Test cJSON_DetachItemFromArray
            cJSON* detached_item = cJSON_DetachItemFromArray(array, valid_index);
            if (detached_item != NULL) {
                // After detaching, we might want to reattach or delete the item
                // For this fuzz test, we'll delete the detached item
                cJSON_Delete(detached_item);
            }
            
            // Break if array becomes empty to avoid infinite loop
            if (cJSON_GetArraySize(array) == 0) {
                break;
            }
        }
    }

    // Reset offset to try deleting items using a different approach
    offset = sizeof(int); // Skip first int used earlier
    
    // Try cJSON_DeleteItemFromArray with some indices
    while (offset + sizeof(int) <= size && cJSON_GetArraySize(array) > 0) {
        int index_to_delete = *(const int*)(data + offset);
        offset += sizeof(int);
        
        if (index_to_delete < 0) {
            index_to_delete = -index_to_delete; // Make positive
        }
        
        int current_size = cJSON_GetArraySize(array);
        if (current_size > 0) {
            int valid_index = index_to_delete % current_size;
            cJSON_DeleteItemFromArray(array, valid_index);
            
            // Break if array becomes empty
            if (cJSON_GetArraySize(array) == 0) {
                break;
            }
        } else {
            break;
        }
    }

    // Finally, clean up the array and all its contents
    cJSON_Delete(array);

    return 0;
}
