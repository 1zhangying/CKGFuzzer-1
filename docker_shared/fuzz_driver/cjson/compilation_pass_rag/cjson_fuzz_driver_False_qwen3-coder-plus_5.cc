#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for cJSON APIs
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to work with
    if (size < 10) {
        return 0;
    }

    // Create root JSON object
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return 0;
    }

    // Use part of the input data to determine number of operations
    size_t pos = 0;
    int num_operations = 0;
    
    if (size >= sizeof(int)) {
        num_operations = *(const int*)data;
        pos += sizeof(int);
        num_operations = abs(num_operations) % 10; // Limit to prevent too many operations
    } else {
        num_operations = 1;
    }

    // Perform operations based on input data
    for (int i = 0; i < num_operations && pos + 2 < size; ++i) {
        unsigned char op_type = data[pos++];
        
        // Ensure we have enough data for key and value lengths
        if (pos + 2 >= size) break;
        
        unsigned char key_len = data[pos++];
        unsigned char val_len = data[pos++];
        
        // Bounds check for key and value lengths
        if (key_len == 0 || val_len == 0) continue;
        if (pos + key_len + val_len > size) break;
        
        // Extract key and value strings from input data
        char *key_str = (char*)malloc(key_len + 1);
        char *val_str = (char*)malloc(val_len + 1);
        
        if (!key_str || !val_str) {
            free(key_str);
            free(val_str);
            break;
        }
        
        memcpy(key_str, data + pos, key_len);
        pos += key_len;
        key_str[key_len] = '\0';
        
        memcpy(val_str, data + pos, val_len);
        pos += val_len;
        val_str[val_len] = '\0';
        
        // Select operation based on op_type
        switch (op_type % 6) {
            case 0: {
                // cJSON_AddItemToObjectCS - Add item with case-sensitive key
                cJSON *new_item = cJSON_CreateString(val_str);
                if (new_item) {
                    cJSON_AddItemToObjectCS(root, key_str, new_item);
                }
                break;
            }
            
            case 1: {
                // cJSON_DeleteItemFromObject - Delete item by key
                cJSON_DeleteItemFromObject(root, key_str);
                break;
            }
            
            case 2: {
                // cJSON_ReplaceItemInObject - Replace existing item
                cJSON *replacement_item = cJSON_CreateString(val_str);
                if (replacement_item) {
                    cJSON_ReplaceItemInObject(root, key_str, replacement_item);
                }
                break;
            }
            
            case 3: {
                // cJSON_AddItemToObject - Add item normally
                cJSON *new_item = cJSON_CreateString(val_str);
                if (new_item) {
                    cJSON_AddItemToObject(root, key_str, new_item);
                }
                break;
            }
            
            case 4: {
                // cJSON_HasObjectItem - Check if key exists
                int has_item = cJSON_HasObjectItem(root, key_str);
                (void)has_item; // Suppress unused variable warning
                break;
            }
            
            case 5: {
                // cJSON_GetObjectItemCaseSensitive - Get item with case-sensitive match
                cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key_str);
                (void)item; // Suppress unused variable warning
                break;
            }
        }
        
        free(key_str);
        free(val_str);
        
        if (pos >= size) break;
    }
    
    // Additional operations to improve coverage
    if (pos + 2 < size) {
        unsigned char key_len = data[pos++];
        if (key_len > 0 && pos + key_len <= size) {
            char *check_key = (char*)malloc(key_len + 1);
            if (check_key) {
                memcpy(check_key, data + pos, key_len);
                check_key[key_len] = '\0';
                
                // Test HasObjectItem and GetObjectItemCaseSensitive
                int has_item = cJSON_HasObjectItem(root, check_key);
                if (has_item) {
                    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, check_key);
                    (void)item;
                    
                    // Try deleting this item
                    cJSON_DeleteItemFromObject(root, check_key);
                }
                
                free(check_key);
            }
        }
    }
    
    // Clean up
    cJSON_Delete(root);
    
    return 0;
}
