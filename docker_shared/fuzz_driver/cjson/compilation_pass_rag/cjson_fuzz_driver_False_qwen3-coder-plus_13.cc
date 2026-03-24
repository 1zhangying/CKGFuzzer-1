#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON array creation and manipulation functions
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < sizeof(double) + sizeof(int)) {
        return 0;
    }

    // Initialize variables
    cJSON* array = NULL;
    cJSON* item = NULL;
    cJSON* doubleArray = NULL;
    cJSON* floatArray = NULL;
    cJSON* intArray = NULL;
    
    // Calculate how many elements we can safely extract from the input data
    size_t offset = 0;
    
    // Extract count for arrays (ensure it's reasonable to prevent large allocations)
    int count = 0;
    if (offset + sizeof(int) <= size) {
        count = *(const int*)(data + offset);
        // Make sure count is positive and not too large to prevent excessive memory allocation
        if (count < 0) count = -count;
        if (count > 100) count = 100;  // Limit to prevent excessive allocation
        
        offset += sizeof(int);
    } else {
        return 0;
    }
    
    // Create arrays based on available data
    
    // Test cJSON_CreateArray
    array = cJSON_CreateArray();
    if (array == NULL) {
        return 0;
    }
    
    // Test cJSON_CreateNumber and cJSON_AddItemToArray
    if (offset + sizeof(double) <= size) {
        double num = *(const double*)(data + offset);
        item = cJSON_CreateNumber(num);
        
        if (item != NULL) {
            // Test cJSON_AddItemToArray
            cJSON_AddItemToArray(array, item);
        }
        offset += sizeof(double);
    }
    
    // Create double array if enough data remains
    if (offset + sizeof(double) * count <= size && count > 0) {
        const double* doubleNumbers = (const double*)(data + offset);
        doubleArray = cJSON_CreateDoubleArray(doubleNumbers, count);
        offset += sizeof(double) * count;
    }
    
    // Create float array if enough data remains
    if (offset + sizeof(float) * count <= size && count > 0) {
        const float* floatNumbers = (const float*)(data + offset);
        floatArray = cJSON_CreateFloatArray(floatNumbers, count);
        offset += sizeof(float) * count;
    }
    
    // Create int array if enough data remains
    if (offset + sizeof(int) * count <= size && count > 0) {
        const int* intNumbers = (const int*)(data + offset);
        intArray = cJSON_CreateIntArray(intNumbers, count);
        offset += sizeof(int) * count;
    }
    
    // Add created arrays to main array if they exist
    if (doubleArray != NULL) {
        cJSON_AddItemToArray(array, doubleArray);
    }
    
    if (floatArray != NULL) {
        cJSON_AddItemToArray(array, floatArray);
    }
    
    if (intArray != NULL) {
        cJSON_AddItemToArray(array, intArray);
    }
    
    // Perform additional operations to increase coverage
    
    // Create another number and try to add it
    if (offset + sizeof(double) <= size) {
        double extraNum = *(const double*)(data + offset);
        cJSON* extraItem = cJSON_CreateNumber(extraNum);
        if (extraItem != NULL) {
            cJSON_AddItemToArray(array, extraItem);
        }
    }
    
    // Clean up all allocated memory
    if (array != NULL) {
        cJSON_Delete(array);
    }
    
    // Note: If doubleArray, floatArray, intArray were added to the main array,
    // they will be deleted when cJSON_Delete(array) is called since they become
    // children of the main array. However, if they weren't added to the array
    // due to failed addition, we need to delete them separately.
    // Since they're added to the array above, no separate deletion is needed.
    
    return 0;
}
