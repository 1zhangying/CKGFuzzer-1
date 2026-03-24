#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// Tests the following APIs: cJSON_Compare, cJSON_GetNumberValue, cJSON_IsString,
// cJSON_GetStringValue, cJSON_IsNumber, cJSON_Duplicate

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be useful
    if (size < 1) {
        return 0;
    }

    // Create a copy of input data to work with
    char *input_copy = (char*)malloc(size + 1);
    if (input_copy == NULL) {
        return 0;
    }
    
    memcpy(input_copy, data, size);
    input_copy[size] = '\0'; // Null terminate for string operations
    
    // Parse the input as JSON
    cJSON *json_root = cJSON_Parse(input_copy);
    if (json_root == NULL) {
        free(input_copy);
        return 0;
    }
    
    // Test cJSON_Duplicate - duplicate the root
    cJSON *duplicated_json = cJSON_Duplicate(json_root, true); // Deep copy
    if (duplicated_json != NULL) {
        // Test cJSON_Compare - compare original with duplicate
        cJSON_bool are_equal = cJSON_Compare(json_root, duplicated_json, true);
        
        // Also test with case insensitive comparison
        cJSON_bool are_equal_case_insensitive = cJSON_Compare(json_root, duplicated_json, false);
        
        // Clean up the duplicate
        cJSON_Delete(duplicated_json);
    }
    
    // Traverse the JSON tree to test various APIs
    cJSON *current = json_root;
    cJSON *array_item = NULL;
    
    // Process the root element
    if (cJSON_IsNumber(current)) {
        // Test cJSON_GetNumberValue
        double num_value = cJSON_GetNumberValue(current);
        // Use the value in some computation to ensure it's used
        volatile double temp = num_value * 2.0;
        (void)temp; // Suppress unused variable warning
    } else if (cJSON_IsString(current)) {
        // Test cJSON_GetStringValue
        const char *str_value = cJSON_GetStringValue(current);
        if (str_value != NULL) {
            // Use the string value in some operation to ensure it's used
            volatile size_t len = strlen(str_value);
            (void)len; // Suppress unused variable warning
        }
    }
    
    // Process children if they exist
    if (current->child != NULL) {
        cJSON *child = current->child;
        while (child != NULL) {
            if (cJSON_IsNumber(child)) {
                // Test cJSON_GetNumberValue
                double num_val = cJSON_GetNumberValue(child);
                volatile double temp_num = num_val / 2.0;
                (void)temp_num;
                
                // Test cJSON_IsNumber
                cJSON_bool is_num = cJSON_IsNumber(child);
                (void)is_num;
            } else if (cJSON_IsString(child)) {
                // Test cJSON_GetStringValue
                const char *str_val = cJSON_GetStringValue(child);
                if (str_val != NULL) {
                    volatile size_t str_len = strlen(str_val);
                    (void)str_len;
                }
                
                // Test cJSON_IsString
                cJSON_bool is_str = cJSON_IsString(child);
                (void)is_str;
            }
            
            // Test cJSON_Duplicate on this child
            cJSON *child_duplicate = cJSON_Duplicate(child, true);
            if (child_duplicate != NULL) {
                // Test comparison between child and its duplicate
                cJSON_bool child_equal = cJSON_Compare(child, child_duplicate, true);
                (void)child_equal;
                
                cJSON_Delete(child_duplicate);
            }
            
            child = child->next;
        }
    }
    
    // If the root is an array, iterate through elements
    if (current->type == cJSON_Array) {
        cJSON_ArrayForEach(array_item, current) {
            if (cJSON_IsNumber(array_item)) {
                double arr_num = cJSON_GetNumberValue(array_item);
                volatile double temp_arr = arr_num + 1.0;
                (void)temp_arr;
            } else if (cJSON_IsString(array_item)) {
                const char *arr_str = cJSON_GetStringValue(array_item);
                if (arr_str != NULL) {
                    volatile size_t arr_len = strlen(arr_str);
                    (void)arr_len;
                }
            }
            
            // Test duplication of array items
            cJSON *arr_dup = cJSON_Duplicate(array_item, true);
            if (arr_dup != NULL) {
                cJSON_Delete(arr_dup);
            }
        }
    }
    
    // If the root is an object, iterate through key-value pairs
    if (current->type == cJSON_Object) {
        cJSON *obj_item = NULL;
        cJSON_ArrayForEach(obj_item, current) {
            if (cJSON_IsNumber(obj_item)) {
                double obj_num = cJSON_GetNumberValue(obj_item);
                volatile double temp_obj = obj_num - 1.0;
                (void)temp_obj;
            } else if (cJSON_IsString(obj_item)) {
                const char *obj_str = cJSON_GetStringValue(obj_item);
                if (obj_str != NULL) {
                    volatile size_t obj_len = strlen(obj_str);
                    (void)obj_len;
                }
            }
            
            // Test duplication of object items
            cJSON *obj_dup = cJSON_Duplicate(obj_item, true);
            if (obj_dup != NULL) {
                cJSON_Delete(obj_dup);
            }
        }
    }
    
    // Clean up
    cJSON_Delete(json_root);
    free(input_copy);
    
    return 0;
}
