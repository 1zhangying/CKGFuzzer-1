#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for cJSON API combination
// This fuzz driver tests the following APIs:
// - cJSON_CreateArray
// - cJSON_CreateString
// - cJSON_CreateNumber
// - cJSON_AddItemToArray
// - cJSON_Delete

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size < 1) {
        return 0;
    }

    // Create a root JSON array
    cJSON* root_array = cJSON_CreateArray();
    if (root_array == NULL) {
        return 0;  // Allocation failed, exit gracefully
    }

    // Parse input data to create various JSON items and add them to the array
    size_t offset = 0;
    
    // Use the first byte to determine how many items we'll try to add
    uint8_t num_items = data[0];
    offset += 1;
    
    // Limit the number of items to prevent excessive allocations
    num_items = num_items % 10;  // At most 10 items
    
    for (uint8_t i = 0; i < num_items && offset < size; ++i) {
        // Determine the type of item to create based on current byte
        uint8_t item_type = data[offset] % 3;  // 0: String, 1: Number, 2: Array
        offset += 1;
        
        cJSON* new_item = NULL;
        
        if (item_type == 0 && offset < size) {
            // Create a string item
            size_t str_len = data[offset] % 10;  // Max 9 chars for string
            offset += 1;
            
            if (offset + str_len <= size) {
                // Create a null-terminated string from input data
                char* str_value = (char*)malloc(str_len + 1);
                if (str_value != NULL) {
                    memcpy(str_value, data + offset, str_len);
                    str_value[str_len] = '\0';
                    
                    new_item = cJSON_CreateString(str_value);
                    free(str_value);  // Free temporary string buffer
                    
                    offset += str_len;
                }
            }
        } 
        else if (item_type == 1 && offset + sizeof(double) <= size) {
            // Create a number item
            double num_value;
            // Copy bytes to avoid alignment issues
            memcpy(&num_value, data + offset, sizeof(double));
            offset += sizeof(double);
            
            new_item = cJSON_CreateNumber(num_value);
        }
        else if (item_type == 2) {
            // Create an empty sub-array
            new_item = cJSON_CreateArray();
        }
        
        // If we successfully created an item, add it to the root array
        if (new_item != NULL) {
            cJSON_bool add_success = cJSON_AddItemToArray(root_array, new_item);
            if (!add_success) {
                // If adding to array failed, delete the item to prevent memory leak
                cJSON_Delete(new_item);
            }
        }
    }
    
    // Perform additional operations to increase coverage
    
    // Try creating more items with different approaches
    if (offset + 1 < size) {
        uint8_t extra_op = data[offset] % 4;
        offset += 1;
        
        if (extra_op == 0 && offset < size) {
            // Create another string
            size_t str_len = data[offset] % 5;
            offset += 1;
            
            if (offset + str_len <= size) {
                char* temp_str = (char*)malloc(str_len + 1);
                if (temp_str != NULL) {
                    memcpy(temp_str, data + offset, str_len);
                    temp_str[str_len] = '\0';
                    
                    cJSON* str_item = cJSON_CreateString(temp_str);
                    if (str_item != NULL) {
                        cJSON_AddItemToArray(root_array, str_item);
                    }
                    free(temp_str);
                    offset += str_len;
                }
            }
        }
        else if (extra_op == 1 && offset + sizeof(int) <= size) {
            // Create number from int bytes
            int int_val;
            memcpy(&int_val, data + offset, sizeof(int));
            offset += sizeof(int);
            
            cJSON* num_item = cJSON_CreateNumber((double)int_val);
            if (num_item != NULL) {
                cJSON_AddItemToArray(root_array, num_item);
            }
        }
        else if (extra_op == 2) {
            // Create nested structure: array inside array
            cJSON* nested_array = cJSON_CreateArray();
            if (nested_array != NULL) {
                cJSON_AddItemToArray(root_array, nested_array);
                
                // Add one item to nested array if possible
                if (offset < size) {
                    cJSON* nested_item = cJSON_CreateNumber(data[offset]);
                    if (nested_item != NULL) {
                        cJSON_AddItemToArray(nested_array, nested_item);
                    }
                }
            }
        }
    }
    
    // Clean up: Delete the entire JSON structure
    cJSON_Delete(root_array);
    
    return 0;
}
