#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON APIs: cJSON_IsObject, cJSON_GetNumberValue, 
// cJSON_HasObjectItem, cJSON_GetStringValue, cJSON_GetObjectItemCaseSensitive,
// cJSON_GetObjectItem

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 1) {
        return 0;
    }

    // Create a copy of input data to work with
    char *input_copy = (char*)malloc(size + 1);
    if (input_copy == NULL) {
        return 0;
    }
    
    memcpy(input_copy, data, size);
    input_copy[size] = '\0';  // Null terminate for string operations

    // Parse the input as JSON
    cJSON *json_root = cJSON_Parse(input_copy);
    if (json_root == NULL) {
        free(input_copy);
        return 0;
    }

    // Test cJSON_IsObject - check if root is an object
    int is_object = cJSON_IsObject(json_root);
    
    // If the root is an object, perform additional tests
    if (is_object) {
        // Prepare a potential key to look for based on input data
        char key_buffer[256];
        size_t key_len = 0;
        
        // Generate a key from input data (limit to reasonable length)
        if (size > 1) {
            key_len = (data[0] % 20) + 1;  // Limit key length to 1-20 chars
            if (key_len > (size - 1)) {
                key_len = (size > 1) ? size - 1 : 1;
            }
            
            for (size_t i = 0; i < key_len && i < sizeof(key_buffer) - 1; ++i) {
                unsigned char c = data[i + 1];
                // Ensure character is printable ASCII to form valid key
                if (c >= 32 && c <= 126) {
                    key_buffer[i] = (char)c;
                } else {
                    key_buffer[i] = 'a' + (c % 26);  // Default to letter
                }
            }
            key_buffer[key_len] = '\0';
        } else {
            strcpy(key_buffer, "test");  // Default key
        }

        // Test cJSON_GetObjectItem - retrieve item by key (case insensitive)
        cJSON *item = cJSON_GetObjectItem(json_root, key_buffer);
        
        // Test cJSON_HasObjectItem - check if key exists
        int has_item = cJSON_HasObjectItem(json_root, key_buffer);
        
        // Test cJSON_GetObjectItemCaseSensitive - retrieve item by key (case sensitive)
        cJSON *case_sensitive_item = cJSON_GetObjectItemCaseSensitive(json_root, key_buffer);
        
        // Process retrieved items if they exist
        if (item != NULL) {
            // Test cJSON_GetNumberValue if item is a number
            double num_value = cJSON_GetNumberValue(item);
            
            // Test cJSON_GetStringValue if item is a string
            const char *str_value = cJSON_GetStringValue(item);
            if (str_value != NULL) {
                // Use the string value (for example, just measure its length)
                volatile size_t str_len = strlen(str_value);
            }
        }
        
        if (case_sensitive_item != NULL) {
            // Test cJSON_GetNumberValue if case sensitive item is a number
            double cs_num_value = cJSON_GetNumberValue(case_sensitive_item);
            
            // Test cJSON_GetStringValue if case sensitive item is a string
            const char *cs_str_value = cJSON_GetStringValue(case_sensitive_item);
            if (cs_str_value != NULL) {
                // Use the string value
                volatile size_t cs_str_len = strlen(cs_str_value);
            }
        }
    } else {
        // If root is not an object, still test number and string getters on root
        double root_num_value = cJSON_GetNumberValue(json_root);
        const char *root_str_value = cJSON_GetStringValue(json_root);
        if (root_str_value != NULL) {
            volatile size_t root_str_len = strlen(root_str_value);
        }
    }

    // Clean up allocated resources
    cJSON_Delete(json_root);
    free(input_copy);
    
    return 0;
}
