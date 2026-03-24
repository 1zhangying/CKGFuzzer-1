#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON APIs: cJSON_GetNumberValue, cJSON_IsString, 
// cJSON_HasObjectItem, cJSON_GetStringValue, cJSON_GetObjectItemCaseSensitive, cJSON_GetObjectItem

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a null-terminated string for JSON parsing
    if (size == 0) {
        return 0;
    }
    
    // Create a copy of the input data to ensure null termination
    char* json_str = (char*)malloc(size + 1);
    if (!json_str) {
        return 0;
    }
    
    memcpy(json_str, data, size);
    json_str[size] = '\0';
    
    // Parse the JSON string
    cJSON* root = cJSON_Parse(json_str);
    if (!root) {
        free(json_str);
        return 0;
    }
    
    // Test cJSON_GetObjectItem with various keys derived from input
    // Extract up to 3 different keys from the input data
    char key1[32] = {0};
    char key2[32] = {0};
    char key3[32] = {0};
    
    // Create keys from input data - use first few bytes as key names
    size_t key_size1 = (size > 0) ? (data[0] % 30) + 1 : 5;  // Limit key length to 30 chars
    key_size1 = (key_size1 > size) ? size : key_size1;
    for (size_t i = 0; i < key_size1 && i < sizeof(key1) - 1; i++) {
        if ((data[i] >= 'a' && data[i] <= 'z') || 
            (data[i] >= 'A' && data[i] <= 'Z') || 
            (data[i] >= '0' && data[i] <= '9')) {
            key1[i] = data[i];
        } else {
            key1[i] = 'a' + (data[i] % 26);  // Map to a-z range
        }
    }
    
    size_t offset1 = key_size1;
    size_t key_size2 = (size > offset1) ? (data[offset1] % 30) + 1 : 5;
    key_size2 = (offset1 + key_size2 > size) ? size - offset1 : key_size2;
    for (size_t i = 0; i < key_size2 && i < sizeof(key2) - 1; i++) {
        if ((data[offset1 + i] >= 'a' && data[offset1 + i] <= 'z') || 
            (data[offset1 + i] >= 'A' && data[offset1 + i] <= 'Z') || 
            (data[offset1 + i] >= '0' && data[offset1 + i] <= '9')) {
            key2[i] = data[offset1 + i];
        } else {
            key2[i] = 'b' + (data[offset1 + i] % 25);  // Map to b-z range
        }
    }
    
    size_t offset2 = offset1 + key_size2;
    size_t key_size3 = (size > offset2) ? (data[offset2] % 30) + 1 : 5;
    key_size3 = (offset2 + key_size3 > size) ? size - offset2 : key_size3;
    for (size_t i = 0; i < key_size3 && i < sizeof(key3) - 1; i++) {
        if ((data[offset2 + i] >= 'a' && data[offset2 + i] <= 'z') || 
            (data[offset2 + i] >= 'A' && data[offset2 + i] <= 'Z') || 
            (data[offset2 + i] >= '0' && data[offset2 + i] <= '9')) {
            key3[i] = data[offset2 + i];
        } else {
            key3[i] = 'c' + (data[offset2 + i] % 24);  // Map to c-z range
        }
    }
    
    // Test cJSON_GetObjectItem with different keys
    cJSON* obj_item1 = cJSON_GetObjectItem(root, key1);
    cJSON* obj_item2 = cJSON_GetObjectItem(root, key2);
    cJSON* obj_item3 = cJSON_GetObjectItem(root, key3);
    
    // Test cJSON_GetObjectItemCaseSensitive with the same keys
    cJSON* obj_case_sensitive1 = cJSON_GetObjectItemCaseSensitive(root, key1);
    cJSON* obj_case_sensitive2 = cJSON_GetObjectItemCaseSensitive(root, key2);
    cJSON* obj_case_sensitive3 = cJSON_GetObjectItemCaseSensitive(root, key3);
    
    // Test cJSON_HasObjectItem to check if keys exist
    int has_key1 = cJSON_HasObjectItem(root, key1);
    int has_key2 = cJSON_HasObjectItem(root, key2);
    int has_key3 = cJSON_HasObjectItem(root, key3);
    
    // Process each retrieved object item
    cJSON* items[] = {obj_item1, obj_item2, obj_item3, obj_case_sensitive1, obj_case_sensitive2, obj_case_sensitive3};
    for (int i = 0; i < 6; i++) {
        cJSON* current_item = items[i];
        
        if (current_item != NULL) {
            // Test cJSON_IsString
            bool is_string = cJSON_IsString(current_item);
            
            // Test cJSON_GetStringValue if it's a string
            if (is_string) {
                const char* str_value = cJSON_GetStringValue(current_item);
                if (str_value != NULL) {
                    // Do something with the string value
                    volatile size_t len = strlen(str_value);
                    (void)len;  // Suppress unused variable warning
                }
            }
            
            // Test cJSON_GetNumberValue regardless of type (it handles non-number types)
            double num_value = cJSON_GetNumberValue(current_item);
            (void)num_value;  // Suppress unused variable warning
        }
    }
    
    // Additional tests with nested objects if root is an object
    if (cJSON_IsObject(root)) {
        // Iterate through all items in the root object
        cJSON* child = root->child;
        while (child != NULL) {
            // Test all APIs on each child
            bool is_string = cJSON_IsString(child);
            double num_val = cJSON_GetNumberValue(child);
            const char* str_val = cJSON_GetStringValue(child);
            
            // Declare variables outside the if block to avoid scope issues
            int has_sub_item = 0;
            cJSON* sub_obj = NULL;
            cJSON* sub_obj_cs = NULL;
            
            // Test object-specific APIs if this child is also an object
            if (cJSON_IsObject(child)) {
                has_sub_item = cJSON_HasObjectItem(child, key1);
                sub_obj = cJSON_GetObjectItem(child, key1);
                sub_obj_cs = cJSON_GetObjectItemCaseSensitive(child, key1);
                
                // Test with the sub-object
                if (sub_obj != NULL) {
                    double sub_num_val = cJSON_GetNumberValue(sub_obj);
                    (void)sub_num_val;
                }
                
                if (sub_obj_cs != NULL) {
                    bool sub_is_string = cJSON_IsString(sub_obj_cs);
                    (void)sub_is_string;
                }
            }
            
            // Use retrieved values to prevent compiler optimizations
            (void)is_string;
            (void)num_val;
            (void)str_val;
            (void)has_sub_item;
            (void)sub_obj;
            (void)sub_obj_cs;
            
            child = child->next;
        }
    }
    
    // Clean up: delete the parsed JSON tree
    cJSON_Delete(root);
    
    // Free allocated string
    free(json_str);
    
    return 0;
}
