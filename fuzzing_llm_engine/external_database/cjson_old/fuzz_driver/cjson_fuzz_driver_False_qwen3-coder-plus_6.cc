#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 10) {
        return 0;
    }

    // Create a root JSON object
    cJSON *root_obj = cJSON_CreateObject();
    if (root_obj == NULL) {
        return 0;
    }

    // Use part of the input data to determine number of operations (limit to reasonable amount)
    size_t num_operations = data[0] % 5 + 1; // At least 1 operation, max 5
    size_t offset = 1;

    // Perform multiple operations based on input data
    for (size_t i = 0; i < num_operations && offset + 2 < size; ++i) {
        uint8_t op_type = data[offset];
        offset++;

        // Extract a short string for the key name (max 8 chars to prevent overflow)
        size_t key_len = data[offset] % 8 + 1; // 1-8 characters
        offset++;
        
        if (offset + key_len > size) {
            break; // Not enough data left
        }

        // Create a null-terminated key string
        char key_str[9]; // 8 chars + null terminator
        memset(key_str, 0, sizeof(key_str));
        for (size_t j = 0; j < key_len && j < 8; ++j) {
            // Ensure printable characters to avoid issues with JSON keys
            uint8_t ch = data[offset + j];
            if (ch >= 32 && ch <= 126) {
                key_str[j] = static_cast<char>(ch);
            } else {
                key_str[j] = '_'; // Replace non-printable chars
            }
        }
        offset += key_len;

        switch (op_type % 3) {
            case 0: {
                // Use cJSON_AddNullToObject
                cJSON *null_val = cJSON_AddNullToObject(root_obj, key_str);
                if (null_val == NULL) {
                    // Failed to add null - continue anyway
                }
                break;
            }
            case 1: {
                // Use cJSON_CreateNull and cJSON_AddItemToObject
                cJSON *null_item = cJSON_CreateNull();
                if (null_item != NULL) {
                    cJSON_bool added = cJSON_AddItemToObject(root_obj, key_str, null_item);
                    if (!added) {
                        // If addition failed, delete the created item to prevent leak
                        cJSON_Delete(null_item);
                    }
                }
                break;
            }
            case 2: {
                // Create a nested object and add it
                cJSON *nested_obj = cJSON_CreateObject();
                if (nested_obj != NULL) {
                    // Add a null value to the nested object
                    cJSON_AddNullToObject(nested_obj, "nested_null");
                    
                    cJSON_bool added = cJSON_AddItemToObject(root_obj, key_str, nested_obj);
                    if (!added) {
                        // If addition failed, delete the created nested object to prevent leak
                        cJSON_Delete(nested_obj);
                    }
                }
                break;
            }
        }
    }

    // Print the JSON object to string (this tests serialization)
    char *json_string = cJSON_Print(root_obj);
    if (json_string != NULL) {
        // Free the printed string
        free(json_string);
    }

    // Clean up: delete the entire JSON object tree
    cJSON_Delete(root_obj);

    return 0;
}
