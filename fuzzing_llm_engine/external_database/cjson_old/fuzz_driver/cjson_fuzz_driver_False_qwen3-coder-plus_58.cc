#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON object manipulation APIs
// Tests the following functions:
// - cJSON_DeleteItemFromObject
// - cJSON_ReplaceItemInObject
// - cJSON_AddItemToObject
// - cJSON_DetachItemFromObject
// - cJSON_GetObjectItem

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a root JSON object to work with
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return 0; // Failed to create root object
    }

    // Use part of the input data to create initial items in the object
    size_t offset = 0;
    
    // Create up to 5 initial items based on input data
    for (int i = 0; i < 5 && offset + 2 < size; i++) {
        // Extract a small portion for key name (max 10 chars)
        size_t key_len = (data[offset] % 10) + 1; // At least 1 char, max 10
        offset++;
        
        if (offset + key_len >= size) break;
        
        // Create a null-terminated key string
        char *key = (char*)malloc(key_len + 1);
        if (!key) break;
        
        memcpy(key, data + offset, key_len);
        key[key_len] = '\0';
        offset += key_len;
        
        if (offset >= size) {
            free(key);
            break;
        }
        
        // Create a value based on next byte
        cJSON *value = NULL;
        switch (data[offset] % 6) {  // Choose from 6 different value types
            case 0:
                value = cJSON_CreateNull();
                break;
            case 1:
                value = cJSON_CreateBool(data[offset] % 2);
                break;
            case 2:
                value = cJSON_CreateNumber((double)(data[offset] * 10));
                break;
            case 3: {
                // String value
                size_t str_len = (data[offset] % 8) + 1; // Max 8 chars
                offset++;
                if (offset + str_len < size) {
                    char *str_val = (char*)malloc(str_len + 1);
                    if (str_val) {
                        memcpy(str_val, data + offset, str_len);
                        str_val[str_len] = '\0';
                        value = cJSON_CreateString(str_val);
                        free(str_val);
                    }
                    offset += str_len - 1; // Compensate for outer increment
                }
                break;
            }
            case 4:
                value = cJSON_CreateArray();
                break;
            case 5:
                value = cJSON_CreateObject();
                break;
        }
        
        offset++;
        
        if (value != NULL) {
            // Add the item to the object
            if (!cJSON_AddItemToObject(root, key, value)) {
                // If addition failed, we need to clean up the value
                cJSON_Delete(value);
            }
        }
        
        free(key);
    }
    
    // Now perform operations based on remaining input data
    while (offset + 1 < size) {
        unsigned char op = data[offset];
        offset++;
        
        if (offset >= size) break;
        
        // Get a key from the input
        size_t key_len = (data[offset] % 10) + 1; // At least 1 char, max 10
        offset++;
        
        if (offset + key_len >= size) break;
        
        char *key = (char*)malloc(key_len + 1);
        if (!key) break;
        
        memcpy(key, data + offset, key_len);
        key[key_len] = '\0';
        offset += key_len;
        
        switch (op % 5) {
            case 0: {
                // Test cJSON_GetObjectItem
                cJSON *found_item = cJSON_GetObjectItem(root, key);
                (void)found_item; // Suppress unused warning
                break;
            }
            case 1: {
                // Test cJSON_AddItemToObject
                cJSON *new_item = cJSON_CreateNumber(data[offset % size]);
                if (new_item) {
                    // Try to add item - might fail if key already exists
                    if (!cJSON_AddItemToObject(root, key, new_item)) {
                        cJSON_Delete(new_item); // Clean up if add failed
                    }
                }
                break;
            }
            case 2: {
                // Test cJSON_ReplaceItemInObject
                cJSON *old_item = cJSON_GetObjectItem(root, key);
                if (old_item) {
                    cJSON *replacement = cJSON_CreateString("replaced");
                    if (replacement) {
                        if (!cJSON_ReplaceItemInObject(root, key, replacement)) {
                            cJSON_Delete(replacement); // Clean up if replace failed
                        }
                    }
                }
                break;
            }
            case 3: {
                // Test cJSON_DetachItemFromObject
                cJSON *detached = cJSON_DetachItemFromObject(root, key);
                if (detached) {
                    // We detached the item, so let's reattach it after deleting
                    cJSON_Delete(detached);
                }
                break;
            }
            case 4: {
                // Test cJSON_DeleteItemFromObject
                cJSON_DeleteItemFromObject(root, key);
                break;
            }
        }
        
        free(key);
        
        if (offset >= size) break;
    }
    
    // Clean up the entire JSON object
    cJSON_Delete(root);
    
    return 0;
}
