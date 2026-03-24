#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for cJSON boolean operations
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables to avoid undefined behavior
    cJSON* false_obj = NULL;
    cJSON* true_obj = NULL;
    cJSON* bool_obj = NULL;
    cJSON* root_obj = NULL;
    
    // Early exit if input is too small to process
    if (size < 1) {
        return 0;
    }
    
    // Create root object to hold test items
    root_obj = cJSON_CreateObject();
    if (!root_obj) {
        return 0; // Allocation failed, exit gracefully
    }
    
    // Use first byte to determine which operations to perform
    uint8_t op_selector = data[0];
    
    // Test cJSON_CreateFalse
    false_obj = cJSON_CreateFalse();
    if (false_obj != NULL) {
        // Test cJSON_IsBool on false object
        if (!cJSON_IsBool(false_obj)) {
            // Error handling - this should always be true for a false object
        }
        
        // Test cJSON_IsTrue on false object (should return false)
        if (cJSON_IsTrue(false_obj)) {
            // This is expected to be false for a false object
        }
        
        // Add false value to root object if we have more data
        if (size > 1) {
            // Use next byte as character for name (ensure it's printable)
            char name[2] = {static_cast<char>((data[1] % 26) + 'a'), '\0'};
            cJSON_AddBoolToObject(root_obj, name, 0); // Add false
        }
    }
    
    // Test cJSON_CreateTrue
    true_obj = cJSON_CreateTrue();
    if (true_obj != NULL) {
        // Test cJSON_IsBool on true object
        if (!cJSON_IsBool(true_obj)) {
            // Error handling - this should always be true for a true object
        }
        
        // Test cJSON_IsTrue on true object (should return true)
        if (!cJSON_IsTrue(true_obj)) {
            // Error handling - this should be true for a true object
        }
        
        // Add true value to root object if we have more data
        if (size > 2) {
            char name[2] = {static_cast<char>((data[2] % 26) + 'A'), '\0'};
            cJSON_AddBoolToObject(root_obj, name, 1); // Add true
        }
    }
    
    // Test cJSON_CreateBool with different values based on input
    if (size > 3) {
        bool value = (data[3] % 2 == 0); // Alternate between true and false
        bool_obj = cJSON_CreateBool(value ? 1 : 0);
        
        if (bool_obj != NULL) {
            // Verify the created boolean has correct type
            if (!cJSON_IsBool(bool_obj)) {
                // Error handling - this should always be true for a boolean object
            }
            
            // Test cJSON_IsTrue depending on what value was created
            if (value && !cJSON_IsTrue(bool_obj)) {
                // Expected true but got false
            } else if (!value && cJSON_IsTrue(bool_obj)) {
                // Expected false but got true
            }
            
            // Add to root object with name derived from input
            if (size > 4) {
                char name[3] = {static_cast<char>((data[4] % 26) + 'a'), 
                               static_cast<char>((data[4+1] % 26) + 'b'), 
                               '\0'};
                if (size > 5) {
                    name[1] = static_cast<char>((data[5] % 26) + 'b');
                }
                cJSON_AddBoolToObject(root_obj, name, value ? 1 : 0);
            }
        }
    }
    
    // Perform additional tests with combinations of operations if more data available
    if (size > 6) {
        // Create another boolean based on more input data
        bool additional_value = (data[6] % 2 == 0);
        cJSON* additional_bool = cJSON_CreateBool(additional_value ? 1 : 0);
        
        if (additional_bool != NULL) {
            // Test IsBool and IsTrue again
            bool is_boolean = cJSON_IsBool(additional_bool);
            bool is_true = cJSON_IsTrue(additional_bool);
            
            // Validate consistency
            if (is_boolean && additional_value != is_true) {
                // Inconsistency detected
            }
            
            cJSON_Delete(additional_bool);
        }
    }
    
    // Clean up all allocated cJSON objects
    if (false_obj) {
        cJSON_Delete(false_obj);
    }
    
    if (true_obj) {
        cJSON_Delete(true_obj);
    }
    
    if (bool_obj && bool_obj != false_obj && bool_obj != true_obj) {
        cJSON_Delete(bool_obj);
    }
    
    if (root_obj) {
        cJSON_Delete(root_obj);
    }
    
    return 0;
}
