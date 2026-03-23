#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation to test cJSON boolean functionality
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 1) {
        return 0;
    }
    
    // Initialize variables to track our JSON objects
    cJSON* false_obj = NULL;
    cJSON* true_obj = NULL;
    cJSON* bool_obj = NULL;
    cJSON* root_obj = NULL;
    
    // Create a root object to add boolean values to
    root_obj = cJSON_CreateObject();
    if (!root_obj) {
        return 0; // Failed to create root object, exit early
    }
    
    // Create a false object using cJSON_CreateFalse
    false_obj = cJSON_CreateFalse();
    if (false_obj) {
        // Verify that the created object is indeed a boolean
        if (!cJSON_IsBool(false_obj)) {
            cJSON_Delete(false_obj);
            false_obj = NULL;
        } else {
            // Verify that it's not true (should be false)
            if (cJSON_IsTrue(false_obj)) {
                // This shouldn't happen since we created a false object
                cJSON_Delete(false_obj);
                false_obj = NULL;
            }
        }
    }
    
    // Create a true object using cJSON_CreateTrue
    true_obj = cJSON_CreateTrue();
    if (true_obj) {
        // Verify that the created object is indeed a boolean
        if (!cJSON_IsBool(true_obj)) {
            cJSON_Delete(true_obj);
            true_obj = NULL;
        } else {
            // Verify that it is true
            if (!cJSON_IsTrue(true_obj)) {
                // This shouldn't happen since we created a true object
                cJSON_Delete(true_obj);
                true_obj = NULL;
            }
        }
    }
    
    // Use the fuzz input to determine the boolean value for cJSON_CreateBool
    cJSON_bool bool_value = (size % 2 == 0) ? 1 : 0; // Alternate based on size
    
    // Create a boolean object using cJSON_CreateBool
    bool_obj = cJSON_CreateBool(bool_value);
    if (bool_obj) {
        // Verify that the created object is indeed a boolean
        if (!cJSON_IsBool(bool_obj)) {
            cJSON_Delete(bool_obj);
            bool_obj = NULL;
        } else {
            // Verify the truth value matches what we expected
            if (bool_value && !cJSON_IsTrue(bool_obj)) {
                // Expected true but got false
                cJSON_Delete(bool_obj);
                bool_obj = NULL;
            } else if (!bool_value && cJSON_IsTrue(bool_obj)) {
                // Expected false but got true
                cJSON_Delete(bool_obj);
                bool_obj = NULL;
            }
        }
    }
    
    // Add boolean values to the root object using cJSON_AddBoolToObject
    // We'll use part of the input data to determine names and values
    if (root_obj) {
        // Add a boolean with name "test1" and value based on first byte of input
        if (size > 0) {
            cJSON_bool val1 = (data[0] % 2 == 0) ? 1 : 0;
            cJSON_AddBoolToObject(root_obj, "test1", val1);
        }
        
        // Add another boolean with name "test2" and value based on second byte of input
        if (size > 1) {
            cJSON_bool val2 = (data[1] % 2 == 0) ? 1 : 0;
            cJSON_AddBoolToObject(root_obj, "test2", val2);
        }
        
        // Add a third boolean with name "test3" and alternating value based on size
        if (size > 2) {
            cJSON_bool val3 = (size % 3 == 0) ? 1 : 0;
            cJSON_AddBoolToObject(root_obj, "test3", val3);
        }
    }
    
    // Perform additional checks on the created objects
    if (false_obj) {
        // Verify it's still a boolean and still false
        if (!cJSON_IsBool(false_obj) || cJSON_IsTrue(false_obj)) {
            // Error state - this shouldn't happen
        }
    }
    
    if (true_obj) {
        // Verify it's still a boolean and still true
        if (!cJSON_IsBool(true_obj) || !cJSON_IsTrue(true_obj)) {
            // Error state - this shouldn't happen
        }
    }
    
    if (bool_obj) {
        // Verify it's still a boolean
        if (!cJSON_IsBool(bool_obj)) {
            // Error state - this shouldn't happen
        }
    }
    
    // Clean up all allocated JSON objects
    cJSON_Delete(false_obj);
    cJSON_Delete(true_obj);
    cJSON_Delete(bool_obj);
    cJSON_Delete(root_obj);
    
    return 0;
}
