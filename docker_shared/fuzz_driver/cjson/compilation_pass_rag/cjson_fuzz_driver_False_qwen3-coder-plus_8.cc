#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON library functions
// This driver creates and manipulates JSON objects using various APIs
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create the main JSON object
    cJSON* root_obj = cJSON_CreateObject();
    if (root_obj == NULL) {
        return 0;
    }

    // Create a temporary buffer to extract strings from input data
    char* temp_buffer = (char*)malloc(size + 1);
    if (temp_buffer == NULL) {
        cJSON_Delete(root_obj);
        return 0;
    }
    
    memcpy(temp_buffer, data, size);
    temp_buffer[size] = '\0';

    // Extract name and value for adding a string to the object
    if (size >= 2) {
        size_t split_point = size / 2;
        
        // Create null-terminated strings for name and value
        char* name_str = (char*)malloc(split_point + 1);
        char* value_str = (char*)malloc((size - split_point) + 1);
        
        if (name_str && value_str) {
            memcpy(name_str, temp_buffer, split_point);
            name_str[split_point] = '\0';
            
            memcpy(value_str, temp_buffer + split_point, size - split_point);
            value_str[size - split_point] = '\0';
            
            // Add string to object
            cJSON* added_string = cJSON_AddStringToObject(root_obj, name_str, value_str);
            // Even if it fails, continue with other operations
            
            // Add number to object using part of the input as a double
            if (split_point > sizeof(double)) {
                double num_value = 0.0;
                size_t copy_size = sizeof(double) > split_point ? split_point : sizeof(double);
                memcpy(&num_value, name_str, copy_size);
                
                cJSON* added_number = cJSON_AddNumberToObject(root_obj, "number_key", num_value);
                // Continue regardless of success/failure
            }
            
            // Add nested object
            cJSON* nested_obj = cJSON_AddObjectToObject(root_obj, "nested");
            if (nested_obj != NULL) {
                // Add a string to the nested object
                cJSON_AddStringToObject(nested_obj, "nested_str", "nested_value");
                
                // Add a number to the nested object
                cJSON_AddNumberToObject(nested_obj, "nested_num", 42.0);
            }
            
            // Try to retrieve an item (using the first part of the input as key if possible)
            if (split_point > 0) {
                cJSON* retrieved_item = cJSON_GetObjectItemCaseSensitive(root_obj, name_str);
                // Use retrieved item if found, but no special action needed
            }
            
            // Attempt to delete an item (try to delete the one we just added)
            cJSON_DeleteItemFromObject(root_obj, name_str);
            
            // Clean up temporary buffers
            free(name_str);
            free(value_str);
        }
    } else {
        // If size is too small, just add a simple static entry
        cJSON_AddStringToObject(root_obj, "default_key", "default_value");
        cJSON_AddNumberToObject(root_obj, "default_number", 123.45);
        
        // Add a nested object
        cJSON* nested_obj = cJSON_AddObjectToObject(root_obj, "nested");
        if (nested_obj != NULL) {
            cJSON_AddStringToObject(nested_obj, "inner_key", "inner_value");
        }
        
        // Try to retrieve an item
        cJSON* retrieved_item = cJSON_GetObjectItemCaseSensitive(root_obj, "default_key");
        
        // Delete an item
        cJSON_DeleteItemFromObject(root_obj, "default_key");
    }

    // Clean up the temporary buffer
    free(temp_buffer);

    // Clean up the entire JSON structure
    cJSON_Delete(root_obj);

    return 0;
}
