#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON boolean functionality
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cJSON *false_item = NULL;
    cJSON *true_item = NULL;
    cJSON *bool_item = NULL;
    cJSON *string_item = NULL;
    
    // Early exit if input is too small
    if (size < 1) {
        return 0;
    }
    
    // Create a false item using cJSON_CreateFalse
    false_item = cJSON_CreateFalse();
    if (false_item == NULL) {
        return 0; // Allocation failed
    }
    
    // Test cJSON_IsFalse - should return true for the false item we created
    int is_false = cJSON_IsFalse(false_item);
    
    // Test cJSON_IsBool - should return true for the false item
    int is_bool = cJSON_IsBool(false_item);
    
    // Test cJSON_IsTrue - should return false for the false item
    int is_true = cJSON_IsTrue(false_item);
    
    // Create a true item using cJSON_CreateBool with true parameter
    true_item = cJSON_CreateBool(1); // 1 means true
    if (true_item != NULL) {
        // Test cJSON_IsTrue - should return true for the true item
        int is_true_result = cJSON_IsTrue(true_item);
        
        // Test cJSON_IsBool - should return true for the true item
        int is_bool_result = cJSON_IsBool(true_item);
        
        // Test cJSON_IsFalse - should return false for the true item
        int is_false_result = cJSON_IsFalse(true_item);
        
        // Clean up the true item
        cJSON_Delete(true_item);
    }
    
    // Create a false item using cJSON_CreateBool with false parameter
    bool_item = cJSON_CreateBool(0); // 0 means false
    if (bool_item != NULL) {
        // Test cJSON_IsFalse - should return true for the false item created via CreateBool
        int is_false_created = cJSON_IsFalse(bool_item);
        
        // Test cJSON_IsBool - should return true for the false item
        int is_bool_created = cJSON_IsBool(bool_item);
        
        // Test cJSON_IsTrue - should return false for the false item
        int is_true_created = cJSON_IsTrue(bool_item);
        
        // Clean up the bool item
        cJSON_Delete(bool_item);
    }
    
    // Test cJSON_GetStringValue with the false item (should return NULL since it's not a string)
    const char* string_value = cJSON_GetStringValue(false_item);
    if (string_value != NULL) {
        // This shouldn't happen since our item is a boolean, not a string
        // But we handle it gracefully
    }
    
    // Create a string item to test cJSON_GetStringValue properly
    // We'll use part of the input data to create a string
    if (size > 1) {
        // Calculate string length (ensure we don't exceed input size)
        size_t str_len = size - 1;
        if (str_len > 100) { // Limit string length to prevent excessive memory usage
            str_len = 100;
        }
        
        char *temp_str = (char*)malloc(str_len + 1);
        if (temp_str != NULL) {
            memcpy(temp_str, data + 1, str_len);
            temp_str[str_len] = '\0'; // Null terminate
            
            string_item = cJSON_CreateString(temp_str);
            if (string_item != NULL) {
                // Now test cJSON_GetStringValue with an actual string
                const char* retrieved_string = cJSON_GetStringValue(string_item);
                if (retrieved_string != NULL) {
                    // String successfully retrieved
                } else {
                    // This shouldn't happen if cJSON_CreateString succeeded
                }
                
                cJSON_Delete(string_item);
            }
            
            free(temp_str);
        }
    }
    
    // Clean up the original false item
    cJSON_Delete(false_item);
    
    return 0;
}
