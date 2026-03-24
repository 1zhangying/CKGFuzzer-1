#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON library functions
// This driver creates arrays, adds items to them, and tests various operations
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < sizeof(double) + 1) {
        return 0;
    }

    // Initialize variables to track our JSON structures
    cJSON* root_array = NULL;
    cJSON* string_item = NULL;
    cJSON* number_item = NULL;
    
    // Create a root array
    root_array = cJSON_CreateArray();
    if (root_array == NULL) {
        return 0; // Failed to create array
    }

    size_t offset = 0;
    
    // Process input data in chunks to create different types of JSON items
    while (offset + sizeof(double) + 1 < size) {
        // Extract a double value from the input data
        double num_val;
        memcpy(&num_val, data + offset, sizeof(double));
        offset += sizeof(double);
        
        // Extract a character to determine whether to create string or number
        uint8_t choice = data[offset];
        offset++;

        if ((choice % 2) == 0) {
            // Create a string item based on remaining data
            size_t str_len = (size - offset) > 0 ? (size - offset) : 0;
            if (str_len > 0) {
                // Limit string length to prevent excessive allocations
                str_len = str_len > 100 ? 100 : str_len;
                
                // Create a null-terminated string from input data
                char* str_data = (char*)malloc(str_len + 1);
                if (str_data != NULL) {
                    memcpy(str_data, data + offset, str_len);
                    str_data[str_len] = '\0';
                    
                    string_item = cJSON_CreateString(str_data);
                    if (string_item != NULL) {
                        // Add the string item to the array
                        cJSON_AddItemToArray(root_array, string_item);
                    }
                    
                    free(str_data);
                }
                
                offset += str_len;
            }
        } else {
            // Create a number item
            number_item = cJSON_CreateNumber(num_val);
            if (number_item != NULL) {
                // Add the number item to the array
                cJSON_AddItemToArray(root_array, number_item);
            }
        }
    }

    // Test getting array size
    int array_size = cJSON_GetArraySize(root_array);
    
    // Perform some operations on the array to increase code coverage
    if (array_size > 0) {
        // Just verify the size we got is reasonable
        if (array_size < 0) {
            // This shouldn't happen with valid cJSON, but check anyway
            cJSON_Delete(root_array);
            return 0;
        }
    }

    // Clean up all allocated memory
    cJSON_Delete(root_array);
    
    return 0;
}
