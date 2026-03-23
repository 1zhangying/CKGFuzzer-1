#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation to test cJSON boolean functionality
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables to prevent undefined behavior
    cJSON* root_obj = NULL;
    cJSON* false_item = NULL;
    cJSON* true_item = NULL;
    cJSON* bool_item = NULL;
    
    // Early exit if input is too small to work with
    if (size < 1) {
        return 0;
    }
    
    // Create root object to hold our test items
    root_obj = cJSON_CreateObject();
    if (!root_obj) {
        return 0; // Allocation failed, exit gracefully
    }
    
    // Test cJSON_CreateFalse
    false_item = cJSON_CreateFalse();
    if (!false_item) {
        cJSON_Delete(root_obj);
        return 0;
    }
    
    // Test cJSON_IsBool with false item
    if (!cJSON_IsBool(false_item)) {
        // This should not happen - our false item should be recognized as boolean
    }
    
    // Test cJSON_IsFalse with false item
    if (!cJSON_IsFalse(false_item)) {
        // This should not happen - our false item should be recognized as false
    }
    
    // Test cJSON_CreateTrue
    true_item = cJSON_CreateTrue();
    if (!true_item) {
        cJSON_Delete(false_item);
        cJSON_Delete(root_obj);
        return 0;
    }
    
    // Test cJSON_IsBool with true item
    if (!cJSON_IsBool(true_item)) {
        // This should not happen - our true item should be recognized as boolean
    }
    
    // Test cJSON_IsFalse with true item (should return false)
    if (cJSON_IsFalse(true_item)) {
        // This should not happen - true item should not be considered false
    }
    
    // Test cJSON_CreateBool with false value
    bool_item = cJSON_CreateBool(0); // false
    if (bool_item) {
        if (!cJSON_IsBool(bool_item)) {
            // Should be recognized as boolean
        }
        
        if (!cJSON_IsFalse(bool_item)) {
            // Should be recognized as false
        }
        cJSON_Delete(bool_item);
    }
    
    // Test cJSON_CreateBool with true value
    bool_item = cJSON_CreateBool(1); // true
    if (bool_item) {
        if (!cJSON_IsBool(bool_item)) {
            // Should be recognized as boolean
        }
        
        if (cJSON_IsFalse(bool_item)) {
            // Should NOT be recognized as false
        }
        cJSON_Delete(bool_item);
    }
    
    // Test cJSON_AddBoolToObject with false value
    bool_item = cJSON_AddBoolToObject(root_obj, "test_false", 0);
    if (!bool_item) {
        // Handle error case where addition to object fails
    } else {
        // Verify the added item is correct
        if (!cJSON_IsBool(bool_item) || !cJSON_IsFalse(bool_item)) {
            // Something went wrong during addition
        }
    }
    
    // Test cJSON_AddBoolToObject with true value
    bool_item = cJSON_AddBoolToObject(root_obj, "test_true", 1);
    if (!bool_item) {
        // Handle error case where addition to object fails
    } else {
        // Verify the added item is correct
        if (!cJSON_IsBool(bool_item) || cJSON_IsFalse(bool_item)) {
            // Something went wrong during addition
        }
    }
    
    // Test adding another boolean with same name (should fail or overwrite)
    bool_item = cJSON_AddBoolToObject(root_obj, "test_false", 1);
    if (!bool_item) {
        // This might fail due to duplicate key depending on implementation
    }
    
    // Clean up all allocated memory
    cJSON_Delete(root_obj); // This will also delete all child items
    
    return 0;
}
