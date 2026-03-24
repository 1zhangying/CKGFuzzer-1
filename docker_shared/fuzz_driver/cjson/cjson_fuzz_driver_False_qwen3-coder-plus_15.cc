#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for cJSON array creation and manipulation functions
// This driver tests the following APIs:
// - cJSON_CreateDoubleArray
// - cJSON_AddItemToArray
// - cJSON_CreateFloatArray
// - cJSON_CreateIntArray
// - cJSON_CreateNumber

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to extract meaningful data
    if (size < sizeof(double) + sizeof(float) + sizeof(int)) {
        return 0;
    }

    // Initialize variables to track our position in the input data
    size_t offset = 0;
    
    // Extract parameters for array creation
    int max_count = 10; // Limit array size to prevent excessive memory usage
    
    // Create arrays based on input data
    
    // 1. Test cJSON_CreateDoubleArray
    if (offset + sizeof(double) * max_count <= size) {
        const double *double_numbers = reinterpret_cast<const double*>(data + offset);
        int actual_double_count = static_cast<int>((size - offset) / sizeof(double));
        if (actual_double_count > max_count) actual_double_count = max_count;
        
        cJSON *double_array = cJSON_CreateDoubleArray(double_numbers, actual_double_count);
        if (double_array != NULL) {
            // Test cJSON_AddItemToArray by adding a new number to this array
            cJSON *new_number = cJSON_CreateNumber(42.5);
            if (new_number != NULL) {
                cJSON_AddItemToArray(double_array, new_number);
            }
            cJSON_Delete(double_array);
        }
        offset += sizeof(double) * actual_double_count;
    }
    
    // 2. Test cJSON_CreateFloatArray
    if (offset + sizeof(float) * max_count <= size && offset < size) {
        size_t remaining_size = size - offset;
        int possible_float_count = static_cast<int>(remaining_size / sizeof(float));
        if (possible_float_count > max_count) possible_float_count = max_count;
        
        if (possible_float_count > 0) {
            const float *float_numbers = reinterpret_cast<const float*>(data + offset);
            
            cJSON *float_array = cJSON_CreateFloatArray(float_numbers, possible_float_count);
            if (float_array != NULL) {
                // Test cJSON_AddItemToArray with another float array
                cJSON *another_float_array = cJSON_CreateFloatArray(float_numbers, 
                    possible_float_count > 1 ? possible_float_count - 1 : 1);
                if (another_float_array != NULL) {
                    cJSON_AddItemToArray(float_array, another_float_array);
                }
                cJSON_Delete(float_array);
            }
        }
        offset += sizeof(float) * max_count;
    }
    
    // 3. Test cJSON_CreateIntArray
    if (offset + sizeof(int) * max_count <= size && offset < size) {
        size_t remaining_size = size - offset;
        int possible_int_count = static_cast<int>(remaining_size / sizeof(int));
        if (possible_int_count > max_count) possible_int_count = max_count;
        
        if (possible_int_count > 0) {
            const int *int_numbers = reinterpret_cast<const int*>(data + offset);
            
            cJSON *int_array = cJSON_CreateIntArray(int_numbers, possible_int_count);
            if (int_array != NULL) {
                // Test cJSON_AddItemToArray by adding a simple number
                cJSON *simple_number = cJSON_CreateNumber(123.0);
                if (simple_number != NULL) {
                    cJSON_AddItemToArray(int_array, simple_number);
                }
                cJSON_Delete(int_array);
            }
        }
        offset += sizeof(int) * max_count;
    }
    
    // 4. Test cJSON_CreateNumber independently
    if (offset + sizeof(double) <= size) {
        double number_val = *reinterpret_cast<const double*>(data + offset);
        cJSON *number_obj = cJSON_CreateNumber(number_val);
        if (number_obj != NULL) {
            cJSON_Delete(number_obj);
        }
    }
    
    // Additional comprehensive test: mix all functions together
    if (size >= sizeof(double) * 3 + sizeof(float) * 2 + sizeof(int) * 2) {
        // Create a double array
        const double *test_doubles = reinterpret_cast<const double*>(data);
        cJSON *main_array = cJSON_CreateDoubleArray(test_doubles, 3);
        
        if (main_array != NULL) {
            // Add a float array to it
            const float *test_floats = reinterpret_cast<const float*>(data + sizeof(double) * 3);
            cJSON *float_subarray = cJSON_CreateFloatArray(test_floats, 2);
            
            if (float_subarray != NULL) {
                cJSON_AddItemToArray(main_array, float_subarray);
            }
            
            // Add an int array to it
            const int *test_ints = reinterpret_cast<const int*>(data + sizeof(double) * 3 + sizeof(float) * 2);
            cJSON *int_subarray = cJSON_CreateIntArray(test_ints, 2);
            
            if (int_subarray != NULL) {
                cJSON_AddItemToArray(main_array, int_subarray);
            }
            
            // Add a single number
            if (sizeof(double) * 3 + sizeof(float) * 2 + sizeof(int) * 2 < size) {
                double extra_num = *(reinterpret_cast<const double*>(
                    data + sizeof(double) * 3 + sizeof(float) * 2 + sizeof(int) * 2));
                cJSON *extra_number = cJSON_CreateNumber(extra_num);
                
                if (extra_number != NULL) {
                    cJSON_AddItemToArray(main_array, extra_number);
                }
            }
            
            cJSON_Delete(main_array);
        }
    }
    
    return 0;
}
