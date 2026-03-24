#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON array operations
// This driver creates arrays, adds items, checks properties, and retrieves items based on fuzzed input
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size < 1) {
        return 0;
    }

    // Create main array to work with
    cJSON *main_array = cJSON_CreateArray();
    if (!main_array) {
        return 0; // Allocation failed
    }

    // Use part of input data to determine how many items to add
    size_t items_count = 0;
    if (size > 0) {
        items_count = data[0] % 10; // Limit to maximum 9 items to prevent excessive allocations
    }

    // Add items to the array based on input data
    for (size_t i = 0; i < items_count && (i + 1) < size; i++) {
        // Create a new cJSON item based on input byte
        cJSON *new_item = NULL;
        
        // Use input byte to decide what type of item to create
        uint8_t item_type = data[i + 1] % 4; // 0-3
        
        switch (item_type) {
            case 0:
                // Create number
                new_item = cJSON_CreateNumber(data[i + 1]);
                break;
            case 1:
                // Create string - use remaining data as string content if available
                if ((i + 2) < size) {
                    size_t str_len = data[i + 2] % 10; // Limit string length
                    if (str_len > 0 && (i + 3 + str_len) <= size) {
                        char *temp_str = (char*)malloc(str_len + 1);
                        if (temp_str) {
                            memcpy(temp_str, data + i + 3, str_len);
                            temp_str[str_len] = '\0';
                            new_item = cJSON_CreateString(temp_str);
                            free(temp_str);
                        }
                    } else if ((i + 2) < size) {
                        // Use single character as string
                        char temp_str[2] = { (char)data[i + 2], '\0' };
                        new_item = cJSON_CreateString(temp_str);
                    }
                }
                break;
            case 2:
                // Create boolean
                new_item = cJSON_CreateBool((data[i + 1] % 2) == 0 ? true : false);
                break;
            case 3:
                // Create null
                new_item = cJSON_CreateNull();
                break;
        }
        
        if (new_item) {
            cJSON_AddItemToArray(main_array, new_item);
        }
    }

    // Verify that the created item is indeed an array
    if (!cJSON_IsArray(main_array)) {
        cJSON_Delete(main_array);
        return 0;
    }

    // Get the size of the array
    int array_size = cJSON_GetArraySize(main_array);

    // Test accessing items by index
    for (int idx = 0; idx < array_size; idx++) {
        cJSON *item = cJSON_GetArrayItem(main_array, idx);
        if (item) {
            // Perform some operations on the retrieved item
            // Just checking if we can access it properly
            (void)item->type; // Access type to make sure item is valid
        }
    }

    // Test edge cases - access with negative index (should return NULL)
    cJSON *negative_idx_item = cJSON_GetArrayItem(main_array, -1);
    if (negative_idx_item != NULL) {
        // This should not happen according to API specification
        cJSON_Delete(main_array);
        return 0;
    }

    // Test accessing beyond array size (if possible)
    if (array_size > 0) {
        cJSON *beyond_item = cJSON_GetArrayItem(main_array, array_size);
        // This might return NULL or another item depending on internal implementation
        // We just want to ensure it doesn't crash
        (void)beyond_item;
    }

    // Clean up - delete the entire array and all contained items
    cJSON_Delete(main_array);

    return 0;
}
