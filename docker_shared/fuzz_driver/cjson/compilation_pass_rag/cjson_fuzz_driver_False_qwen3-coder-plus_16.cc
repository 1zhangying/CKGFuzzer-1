#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>
#include <sstream>

// Fuzz driver implementation for cJSON library functions
// This fuzzer tests the following API functions:
// - cJSON_Delete
// - cJSON_AddItemToArray
// - cJSON_CreateIntArray
// - cJSON_CreateArray
// - cJSON_CreateNumber

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < sizeof(int)) {
        return 0;
    }

    // Parse input data to extract parameters for testing
    size_t offset = 0;
    
    // Extract an integer to determine how many numbers to process
    int num_count = 0;
    if (offset + sizeof(int) <= size) {
        num_count = *(const int*)(data + offset);
        offset += sizeof(int);
    } else {
        return 0;
    }
    
    // Limit the number of elements to prevent excessive memory allocation
    num_count = abs(num_count) % 1000; // Cap at 1000 elements
    
    // Create an array to hold integers for cJSON_CreateIntArray
    int* int_array = nullptr;
    cJSON* json_array = nullptr;
    cJSON* created_number = nullptr;
    
    if (num_count > 0 && offset + num_count * sizeof(int) <= size) {
        // Allocate memory for integer array
        int_array = (int*)malloc(num_count * sizeof(int));
        if (int_array != nullptr) {
            // Copy integers from input data
            for (int i = 0; i < num_count && offset + sizeof(int) <= size; i++) {
                int_array[i] = *(const int*)(data + offset);
                offset += sizeof(int);
            }
            
            // Test cJSON_CreateIntArray - creates a JSON array from integer array
            json_array = cJSON_CreateIntArray(int_array, num_count);
            if (json_array != nullptr) {
                // Test cJSON_AddItemToArray - add another number to the array
                if (offset + sizeof(double) <= size) {
                    double additional_num = *(const double*)(data + offset);
                    cJSON* additional_item = cJSON_CreateNumber(additional_num);
                    
                    if (additional_item != nullptr) {
                        // Add the new item to the existing array
                        cJSON_AddItemToArray(json_array, additional_item);
                    }
                }
                
                // Test cJSON_CreateNumber independently
                if (offset + sizeof(double) <= size) {
                    double test_num = *(const double*)(data + offset);
                    created_number = cJSON_CreateNumber(test_num);
                    
                    if (created_number != nullptr) {
                        // Add this number to our array as well
                        cJSON_AddItemToArray(json_array, created_number);
                        // Set created_number to null since it's now managed by the array
                        created_number = nullptr;
                    }
                }
                
                // Test cJSON_CreateArray separately
                cJSON* standalone_array = cJSON_CreateArray();
                if (standalone_array != nullptr) {
                    // Add some items to this standalone array
                    if (offset + sizeof(double) <= size) {
                        double arr_num = *(const double*)(data + offset);
                        cJSON* arr_item = cJSON_CreateNumber(arr_num);
                        
                        if (arr_item != nullptr) {
                            cJSON_AddItemToArray(standalone_array, arr_item);
                        } else {
                            // Clean up standalone array if we couldn't add an item
                            cJSON_Delete(standalone_array);
                            standalone_array = nullptr;
                        }
                    } else {
                        // Clean up standalone array if we don't have enough data
                        cJSON_Delete(standalone_array);
                        standalone_array = nullptr;
                    }
                }
                
                // Clean up main array
                cJSON_Delete(json_array);
                json_array = nullptr;
            }
            
            // Free the integer array
            free(int_array);
            int_array = nullptr;
        }
    }
    
    // Additional test: create an array and add items manually
    cJSON* temp_array = cJSON_CreateArray();
    if (temp_array != nullptr) {
        // Create a few number items and add them to the array
        if (offset + sizeof(double) <= size) {
            double val1 = *(const double*)(data + offset);
            cJSON* item1 = cJSON_CreateNumber(val1);
            
            if (item1 != nullptr) {
                cJSON_AddItemToArray(temp_array, item1);
                
                if (offset + sizeof(double) <= size - sizeof(double)) {
                    double val2 = *(const double*)(data + offset + sizeof(double));
                    cJSON* item2 = cJSON_CreateNumber(val2);
                    
                    if (item2 != nullptr) {
                        cJSON_AddItemToArray(temp_array, item2);
                    }
                }
            }
        }
        
        // Clean up the temporary array
        cJSON_Delete(temp_array);
        temp_array = nullptr;
    }
    
    // Ensure all dynamically allocated memory is freed
    if (json_array != nullptr) {
        cJSON_Delete(json_array);
    }
    
    if (created_number != nullptr && json_array == nullptr) {
        // Only delete if not already part of an array
        cJSON_Delete(created_number);
    }
    
    if (int_array != nullptr) {
        free(int_array);
    }
    
    return 0;
}
