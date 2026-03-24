#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON boolean functionality
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables to prevent undefined behavior
    cJSON* false_item = NULL;
    cJSON* true_item = NULL;
    cJSON* bool_item = NULL;
    
    // Check if we have enough data to proceed
    if (size < 1) {
        return 0;
    }
    
    // Use first byte to determine which operations to perform
    uint8_t op_selector = data[0];
    size_t remaining_size = size > 0 ? size - 1 : 0;
    const uint8_t* remaining_data = size > 0 ? data + 1 : data;
    
    // Test cJSON_CreateFalse
    false_item = cJSON_CreateFalse();
    if (false_item != NULL) {
        // Verify the created item is indeed a boolean and specifically false
        if (!cJSON_IsBool(false_item)) {
            // Error: Created item should be a boolean
        } else {
            if (!cJSON_IsFalse(false_item)) {
                // Error: Created item should be false
            }
            if (cJSON_IsTrue(false_item)) {
                // Error: False item should not be true
            }
        }
        
        // Test with remaining data to potentially affect other operations
        if (remaining_size > 0 && (op_selector & 0x01)) {
            // Create a boolean based on next byte
            bool bool_val = remaining_data[0] % 2 == 0;
            bool_item = cJSON_CreateBool(bool_val);
            if (bool_item != NULL) {
                if (!cJSON_IsBool(bool_item)) {
                    // Error: Created item should be a boolean
                } else {
                    if (bool_val) {
                        if (!cJSON_IsTrue(bool_item)) {
                            // Error: Should be true when bool_val is true
                        }
                        if (cJSON_IsFalse(bool_item)) {
                            // Error: Should not be false when bool_val is true
                        }
                    } else {
                        if (!cJSON_IsFalse(bool_item)) {
                            // Error: Should be false when bool_val is false
                        }
                        if (cJSON_IsTrue(bool_item)) {
                            // Error: Should not be true when bool_val is false
                        }
                    }
                }
                
                // Clean up bool_item
                cJSON_Delete(bool_item);
                bool_item = NULL;
            }
        }
        
        // Clean up false_item
        cJSON_Delete(false_item);
        false_item = NULL;
    }
    
    // Test cJSON_CreateTrue if we have more operations to perform
    if ((op_selector & 0x02) && remaining_size > 0) {
        true_item = cJSON_CreateTrue();
        if (true_item != NULL) {
            // Verify the created item is indeed a boolean and specifically true
            if (!cJSON_IsBool(true_item)) {
                // Error: Created item should be a boolean
            } else {
                if (!cJSON_IsTrue(true_item)) {
                    // Error: Created item should be true
                }
                if (cJSON_IsFalse(true_item)) {
                    // Error: True item should not be false
                }
            }
            
            // Test with additional data
            if (remaining_size > 1 && (op_selector & 0x04)) {
                // Create another boolean with second byte
                bool second_bool_val = remaining_data[1] % 2 == 0;
                bool_item = cJSON_CreateBool(second_bool_val);
                if (bool_item != NULL) {
                    if (!cJSON_IsBool(bool_item)) {
                        // Error: Created item should be a boolean
                    } else {
                        if (second_bool_val) {
                            if (!cJSON_IsTrue(bool_item)) {
                                // Error: Should be true when bool_val is true
                            }
                        } else {
                            if (!cJSON_IsFalse(bool_item)) {
                                // Error: Should be false when bool_val is false
                            }
                        }
                    }
                    
                    // Test null pointer handling for boolean checks
                    if (cJSON_IsBool(NULL)) {
                        // Error: IsBool should return false for NULL
                    }
                    if (cJSON_IsTrue(NULL)) {
                        // Error: IsTrue should return false for NULL
                    }
                    if (cJSON_IsFalse(NULL)) {
                        // Error: IsFalse should return false for NULL
                    }
                    
                    // Clean up bool_item
                    cJSON_Delete(bool_item);
                    bool_item = NULL;
                }
            }
            
            // Clean up true_item
            cJSON_Delete(true_item);
            true_item = NULL;
        }
    }
    
    // Perform some additional testing based on remaining data
    if (remaining_size > 2 && (op_selector & 0x08)) {
        // Create multiple boolean values to test memory management
        cJSON* temp_items[4] = {NULL};
        int created_count = 0;
        
        for (int i = 0; i < 4 && (2 + i) < remaining_size; i++) {
            bool val = remaining_data[2 + i] % 2 == 0;
            temp_items[i] = cJSON_CreateBool(val);
            if (temp_items[i] != NULL) {
                created_count++;
                
                // Verify the created boolean
                if (!cJSON_IsBool(temp_items[i])) {
                    // Error: Created item should be a boolean
                }
                
                if (val) {
                    if (!cJSON_IsTrue(temp_items[i])) {
                        // Error: Should be true when val is true
                    }
                } else {
                    if (!cJSON_IsFalse(temp_items[i])) {
                        // Error: Should be false when val is false
                    }
                }
            }
        }
        
        // Clean up all created items
        for (int i = 0; i < 4; i++) {
            if (temp_items[i] != NULL) {
                cJSON_Delete(temp_items[i]);
                temp_items[i] = NULL;
            }
        }
    }
    
    // Test edge cases and ensure no memory leaks
    // All allocated cJSON objects should be deleted before returning
    
    return 0;
}
