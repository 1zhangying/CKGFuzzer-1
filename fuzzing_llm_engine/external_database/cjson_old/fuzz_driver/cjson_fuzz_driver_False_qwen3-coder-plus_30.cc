#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON array manipulation functions
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cJSON *root = NULL;
    cJSON *array = NULL;
    cJSON *new_item = NULL;
    cJSON *temp_item = NULL;
    char *input_str = NULL;
    
    // Early exit if input is too small
    if (size < 1) {
        return 0;
    }
    
    // Allocate and copy input data to null-terminated string for JSON parsing
    input_str = (char*)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0';
    
    // Try to parse the input as JSON
    root = cJSON_Parse(input_str);
    
    // If parsing fails, create an empty array for testing
    if (!root) {
        array = cJSON_CreateArray();
        if (!array) {
            free(input_str);
            return 0;
        }
    } else {
        // If root is an array, use it; otherwise create a new one
        if (cJSON_IsArray(root)) {
            array = root;
            root = NULL; // Transfer ownership to array variable
        } else {
            cJSON_Delete(root);
            array = cJSON_CreateArray();
            if (!array) {
                free(input_str);
                return 0;
            }
        }
    }
    
    // Test cJSON_GetArraySize
    int array_size = cJSON_GetArraySize(array);
    
    // Perform operations based on input data
    if (size > 0) {
        // Add items to array based on input data
        for (size_t i = 0; i < size && i < 10; i++) { // Limit additions to prevent excessive memory usage
            // Create different types of items based on input byte
            unsigned char byte_val = data[i];
            if (byte_val % 3 == 0) {
                new_item = cJSON_CreateNumber(byte_val);
            } else if (byte_val % 3 == 1) {
                new_item = cJSON_CreateString("test_string");
            } else {
                new_item = cJSON_CreateBool((byte_val % 2) ? 1 : 0);
            }
            
            if (new_item) {
                cJSON_AddItemToArray(array, new_item);
            }
        }
        
        // Update array size after additions
        array_size = cJSON_GetArraySize(array);
        
        // Test cJSON_GetArrayItem with various indices
        for (int idx = 0; idx < array_size && idx < 10; idx++) {
            temp_item = cJSON_GetArrayItem(array, idx);
            if (temp_item) {
                // Access the item - just verify it exists
                (void)cJSON_IsString(temp_item);
                (void)cJSON_IsNumber(temp_item);
                (void)cJSON_IsBool(temp_item);
            }
        }
        
        // Test deletion if array has items
        if (array_size > 0) {
            // Delete from end to avoid index shifting issues
            for (int del_idx = array_size - 1; del_idx >= 0 && del_idx >= array_size - 3; del_idx--) {
                if (del_idx >= 0) {
                    cJSON_DeleteItemFromArray(array, del_idx);
                }
            }
        }
    }
    
    // Create another array to test more functionality
    cJSON *secondary_array = cJSON_CreateArray();
    if (secondary_array) {
        // Add some items to secondary array
        cJSON *num_item = cJSON_CreateNumber(42);
        if (num_item) {
            cJSON_AddItemToArray(secondary_array, num_item);
        }
        
        cJSON *str_item = cJSON_CreateString("fuzz_test");
        if (str_item) {
            cJSON_AddItemToArray(secondary_array, str_item);
        }
        
        // Get size of secondary array
        int sec_array_size = cJSON_GetArraySize(secondary_array);
        
        // Try to get items from secondary array
        for (int i = 0; i < sec_array_size; i++) {
            cJSON *item = cJSON_GetArrayItem(secondary_array, i);
            if (item) {
                (void)item; // Use the item to avoid warnings
            }
        }
        
        // Clean up secondary array
        cJSON_Delete(secondary_array);
    }
    
    // Test cJSON_GetObjectItem - create a dummy object to test with
    cJSON *obj = cJSON_CreateObject();
    if (obj) {
        cJSON_AddItemToObject(obj, "test_key", cJSON_CreateString("test_value"));
        
        // Try to get an object item (this won't work if our main array isn't an object,
        // but we're testing the function anyway)
        cJSON *found_item = cJSON_GetObjectItem(obj, "test_key");
        if (found_item) {
            (void)found_item; // Use to avoid warning
        }
        
        // Also try to get from the original array (if it was actually an object)
        if (root) {
            cJSON *obj_item = cJSON_GetObjectItem(root, "nonexistent_key");
            (void)obj_item; // Use to avoid warning
        }
        
        cJSON_Delete(obj);
    }
    
    // Final cleanup
    if (array) {
        cJSON_Delete(array);
    }
    
    if (root) {
        cJSON_Delete(root);
    }
    
    free(input_str);
    
    return 0;
}
