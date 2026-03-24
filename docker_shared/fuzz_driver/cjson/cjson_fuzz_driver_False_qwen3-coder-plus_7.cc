#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests the following APIs:
// - cJSON_CreateObject
// - cJSON_CreateNumber
// - cJSON_AddNumberToObject
// - cJSON_AddItemToObject
// - cJSON_Print
// - cJSON_Delete

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size < sizeof(double)) {
        return 0;
    }

    // Initialize variables to avoid undefined behavior
    cJSON *root_obj = NULL;
    cJSON *nested_obj = NULL;
    cJSON *number_item = NULL;
    char *json_string = NULL;
    
    // Create the root JSON object
    root_obj = cJSON_CreateObject();
    if (root_obj == NULL) {
        return 0; // Allocation failed, exit gracefully
    }

    // Extract a double value from input data for creating a number
    if (size >= sizeof(double)) {
        double num_value = 0.0;
        memcpy(&num_value, data, sizeof(double));
        
        // Create a number item
        number_item = cJSON_CreateNumber(num_value);
        if (number_item != NULL) {
            // Add the number to the root object with a fixed key
            if (!cJSON_AddItemToObject(root_obj, "number_key", number_item)) {
                // If addition fails, we need to delete the item ourselves
                cJSON_Delete(number_item);
                number_item = NULL;
            }
        }
    }

    // Create a nested object
    nested_obj = cJSON_CreateObject();
    if (nested_obj != NULL) {
        // Add the nested object to the root object
        if (!cJSON_AddItemToObject(root_obj, "nested_obj", nested_obj)) {
            // If addition fails, delete the nested object ourselves
            cJSON_Delete(nested_obj);
            nested_obj = NULL;
        } else {
            // Add a number to the nested object
            if (size >= sizeof(double) * 2) {
                double nested_num = 0.0;
                memcpy(&nested_num, data + sizeof(double), sizeof(double));
                
                if (!cJSON_AddNumberToObject(nested_obj, "nested_number", nested_num)) {
                    // Handle error if adding number to nested object fails
                }
            }
        }
    }

    // Print the JSON object to a string
    json_string = cJSON_Print(root_obj);
    if (json_string != NULL) {
        // Optionally do something with the printed JSON string
        // For example, check its length or contents
        size_t printed_len = strlen(json_string);
        (void)printed_len; // Suppress unused variable warning
        
        // Free the printed string
        cJSON_free(json_string);
    }

    // Clean up: Delete the entire JSON object tree
    cJSON_Delete(root_obj);

    return 0;
}
