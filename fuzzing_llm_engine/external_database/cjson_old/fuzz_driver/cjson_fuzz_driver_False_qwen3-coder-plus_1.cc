#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests the following APIs:
// - cJSON_ParseWithLength
// - cJSON_AddObjectToObject
// - cJSON_AddArrayToObject
// - cJSON_AddStringToObject
// - cJSON_CreateArray
// - cJSON_Print

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cJSON *root = NULL;
    cJSON *nested_obj = NULL;
    cJSON *nested_array = NULL;
    char *json_string = NULL;
    
    // Early exit if input is too small
    if (size < 1) {
        return 0;
    }
    
    // Create a copy of input data to ensure null termination for string operations
    char *input_copy = (char*)malloc(size + 1);
    if (!input_copy) {
        return 0;
    }
    memcpy(input_copy, data, size);
    input_copy[size] = '\0';
    
    // Parse the input data as JSON
    root = cJSON_ParseWithLength(input_copy, size);
    
    // If parsing fails, create a basic object to continue testing other APIs
    if (!root) {
        root = cJSON_CreateObject();
        if (!root) {
            free(input_copy);
            return 0;
        }
    }
    
    // Test cJSON_AddStringToObject - extract a name from input data
    if (size > 10) {  // Need enough data for both name and value
        // Use first few bytes as name (ensure null termination)
        size_t name_len = (size > 20) ? 10 : size / 2;
        char *name = (char*)malloc(name_len + 1);
        if (name) {
            memcpy(name, input_copy, name_len);
            name[name_len] = '\0';
            
            // Use remaining data as string value
            size_t value_start = name_len;
            size_t value_len = size - value_start;
            char *value = (char*)malloc(value_len + 1);
            if (value) {
                memcpy(value, input_copy + value_start, value_len);
                value[value_len] = '\0';
                
                cJSON_AddStringToObject(root, name, value);
                
                free(value);
            }
            free(name);
        }
    } else {
        // Use fixed names/values if input is too small
        cJSON_AddStringToObject(root, "key1", "value1");
    }
    
    // Test cJSON_AddObjectToObject
    nested_obj = cJSON_AddObjectToObject(root, "nested_object");
    if (nested_obj) {
        cJSON_AddStringToObject(nested_obj, "nested_key", "nested_value");
    }
    
    // Test cJSON_CreateArray and cJSON_AddArrayToObject
    cJSON *new_array = cJSON_CreateArray();
    if (new_array) {
        // Add some elements to the array if we have enough data
        if (size > 5) {
            char *arr_element = (char*)malloc(6);
            if (arr_element) {
                memcpy(arr_element, input_copy, 5);
                arr_element[5] = '\0';
                cJSON *str_elem = cJSON_CreateString(arr_element);
                if (str_elem) {
                    cJSON_AddItemToArray(new_array, str_elem);
                }
                free(arr_element);
            }
        } else {
            cJSON_AddItemToArray(new_array, cJSON_CreateString("default"));
        }
        
        // Add the created array to the root object
        nested_array = cJSON_AddArrayToObject(root, "nested_array");
        if (nested_array) {
            // Move items from new_array to nested_array by reusing them
            cJSON *current = new_array->child;
            while (current) {
                cJSON *next = current->next; // Save next before removing
                cJSON_DetachItemViaPointer(new_array, current);
                cJSON_AddItemToArray(nested_array, current);
                current = next;
            }
        } else {
            // If we couldn't add to object, clean up the array
            cJSON_Delete(new_array);
        }
    }
    
    // Test cJSON_Print to serialize the JSON object back to string
    json_string = cJSON_Print(root);
    if (json_string) {
        // Free the printed string to prevent memory leak
        free(json_string);
    }
    
    // Clean up all allocated resources
    cJSON_Delete(root);
    free(input_copy);
    
    return 0;
}
