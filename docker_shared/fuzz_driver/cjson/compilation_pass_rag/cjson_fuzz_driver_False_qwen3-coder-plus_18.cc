#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for cJSON library APIs
// This driver tests various cJSON operations including creating objects,
// adding number values to objects, and retrieving number values.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < sizeof(double) + 1) {
        return 0;
    }

    // Create a root JSON object
    cJSON* root_obj = cJSON_CreateObject();
    if (root_obj == NULL) {
        return 0;  // Failed to create object, exit early
    }

    // Create a second JSON object to test nested operations
    cJSON* nested_obj = cJSON_CreateObject();
    if (nested_obj == NULL) {
        cJSON_Delete(root_obj);
        return 0;
    }

    // Process input data in chunks to extract parameters
    size_t offset = 0;
    
    // Extract a double value from input data
    if (offset + sizeof(double) <= size) {
        double number_val = 0.0;
        memcpy(&number_val, data + offset, sizeof(double));
        offset += sizeof(double);

        // Test cJSON_CreateNumber - creates a cJSON number item
        cJSON* number_item = cJSON_CreateNumber(number_val);
        if (number_item != NULL) {
            // Test cJSON_IsNumber - verify the item is a number
            if (cJSON_IsNumber(number_item)) {
                // Test cJSON_GetNumberValue - retrieve the numeric value
                double retrieved_value = cJSON_GetNumberValue(number_item);
                
                // Test cJSON_AddNumberToObject - add number to root object
                // Using a fixed name for testing purposes since we need a valid string
                cJSON* added_number = cJSON_AddNumberToObject(root_obj, "test_num", number_val);
                if (added_number == NULL) {
                    // Handle error if addition failed
                    cJSON_Delete(number_item);
                } else {
                    // Verify that the added item is indeed a number
                    if (cJSON_IsNumber(added_number)) {
                        double check_value = cJSON_GetNumberValue(added_number);
                        // Use the retrieved value to avoid compiler warnings
                        (void)check_value;
                    }
                }
            }
            
            // Add the number item to nested object using AddItemToObject
            if (offset + 1 < size && number_item->next == NULL) {
                // Add the same number item to nested object
                int add_result = cJSON_AddItemToObject(nested_obj, "nested_num", number_item);
                if (add_result) {
                    // Successfully added, now try to retrieve it back
                    cJSON* retrieved_item = cJSON_GetObjectItem(nested_obj, "nested_num");
                    if (retrieved_item != NULL && cJSON_IsNumber(retrieved_item)) {
                        double nested_value = cJSON_GetNumberValue(retrieved_item);
                        (void)nested_value;  // Use the value to avoid compiler warnings
                    }
                }
                // Note: Don't delete number_item here since it might be owned by nested_obj after AddItemToObject
            } else {
                // If we can't add to nested object, just delete the number_item
                cJSON_Delete(number_item);
            }
        }
    }

    // Add nested object to root object if possible
    if (offset + 1 < size) {
        int add_nested_result = cJSON_AddItemToObject(root_obj, "nested_obj", nested_obj);
        if (!add_nested_result) {
            // If adding nested object failed, clean up nested object separately
            cJSON_Delete(nested_obj);
        }
        // Otherwise nested_obj is now owned by root_obj
    } else {
        // If not adding to root, delete nested object
        cJSON_Delete(nested_obj);
    }

    // Perform additional operations based on remaining data
    if (offset + sizeof(double) <= size) {
        double second_number = 0.0;
        memcpy(&second_number, data + offset, sizeof(double));
        
        // Add another number to the root object
        cJSON* second_added = cJSON_AddNumberToObject(root_obj, "second_num", second_number);
        if (second_added != NULL) {
            // Verify the operation worked
            if (cJSON_IsNumber(second_added)) {
                double verified_value = cJSON_GetNumberValue(second_added);
                (void)verified_value;
            }
        }
        offset += sizeof(double);
    }

    // Clean up the entire JSON structure
    cJSON_Delete(root_obj);

    return 0;
}
