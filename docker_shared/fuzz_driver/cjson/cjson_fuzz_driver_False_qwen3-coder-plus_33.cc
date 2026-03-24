#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON APIs: cJSON_AddNumberToObject, cJSON_GetNumberValue,
// cJSON_GetObjectItem, cJSON_CreateNumber, cJSON_IsNumber

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < sizeof(double) + 1) {
        return 0;
    }

    // Initialize variables to parse input data
    size_t offset = 0;
    
    // Extract a double value from input for number creation
    if (offset + sizeof(double) > size) {
        return 0;
    }
    double number_value = 0.0;
    memcpy(&number_value, data + offset, sizeof(double));
    offset += sizeof(double);

    // Extract a character for name string generation (limit length to prevent huge allocations)
    size_t name_length = 0;
    if (offset < size) {
        name_length = data[offset] % 32; // Limit to reasonable length (max 31 chars)
        offset++;
    } else {
        name_length = 0;
    }

    // Ensure we have enough data for the name string
    if (offset + name_length > size) {
        name_length = size - offset;
    }

    // Create a null-terminated name string from input data
    char *name_str = nullptr;
    if (name_length > 0) {
        name_str = (char*)malloc(name_length + 1);
        if (!name_str) {
            return 0;
        }
        
        // Copy data and ensure null termination
        memcpy(name_str, data + offset, name_length);
        name_str[name_length] = '\0';
    }

    // Create root JSON object
    cJSON *root_obj = cJSON_CreateObject();
    if (!root_obj) {
        free(name_str);
        return 0;
    }

    // Test cJSON_CreateNumber API
    cJSON *number_item = cJSON_CreateNumber(number_value);
    if (!number_item) {
        free(name_str);
        cJSON_Delete(root_obj);
        return 0;
    }

    // Add the number item to the root object if we have a valid name
    cJSON *added_number_item = nullptr;
    if (name_str && strlen(name_str) > 0) {
        added_number_item = cJSON_AddNumberToObject(root_obj, name_str, number_value);
    }

    // Test cJSON_IsNumber API
    bool is_num_root = cJSON_IsNumber(number_item);
    bool is_num_added = false;
    if (added_number_item) {
        is_num_added = cJSON_IsNumber(added_number_item);
    }

    // Test cJSON_GetNumberValue API
    double retrieved_value = cJSON_GetNumberValue(number_item);
    double retrieved_added_value = 0.0;
    if (added_number_item) {
        retrieved_added_value = cJSON_GetNumberValue(added_number_item);
    }

    // Test cJSON_GetObjectItem API
    cJSON *retrieved_item = nullptr;
    if (name_str && strlen(name_str) > 0) {
        retrieved_item = cJSON_GetObjectItem(root_obj, name_str);
    }

    // Validate retrieved item if it exists
    if (retrieved_item) {
        bool is_retrieved_num = cJSON_IsNumber(retrieved_item);
        double retrieved_val = cJSON_GetNumberValue(retrieved_item);
        
        // Perform additional operations on retrieved item if needed
        (void)is_retrieved_num; // Suppress unused variable warning
        (void)retrieved_val;    // Suppress unused variable warning
    }

    // Clean up resources
    free(name_str);
    cJSON_Delete(number_item);      // Delete separately created number item
    cJSON_Delete(root_obj);         // This also deletes all child items including added_number_item

    return 0;
}
