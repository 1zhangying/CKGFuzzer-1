#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests various cJSON object creation and manipulation APIs
// It creates a root JSON object and adds different types of items to it

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create the root JSON object
    cJSON* root_obj = cJSON_CreateObject();
    if (root_obj == NULL) {
        return 0;
    }

    size_t offset = 0;

    // Extract a name for the number object (first 4 bytes as length, then string)
    if (offset + sizeof(uint32_t) <= size) {
        uint32_t name_len = *(uint32_t*)(data + offset);
        offset += sizeof(uint32_t);
        
        // Ensure we have enough data for the name
        if (name_len > 0 && offset + name_len <= size) {
            // Make sure the name is null-terminated by copying to a local buffer
            char* num_name = (char*)malloc(name_len + 1);
            if (num_name != NULL) {
                memcpy(num_name, data + offset, name_len);
                num_name[name_len] = '\0';
                
                // Extract a double value from the remaining data
                if (offset + name_len + sizeof(double) <= size) {
                    double number_val = *(double*)(data + offset + name_len);
                    
                    // Add number to object
                    cJSON* number_item = cJSON_AddNumberToObject(root_obj, num_name, number_val);
                    if (number_item != NULL) {
                        // Successfully added number item
                    }
                }
                
                free(num_name);
            }
            
            offset += name_len;
        }
    }

    // Extract a name for the string object
    if (offset + sizeof(uint32_t) <= size) {
        uint32_t str_name_len = *(uint32_t*)(data + offset);
        offset += sizeof(uint32_t);
        
        if (str_name_len > 0 && offset + str_name_len <= size) {
            char* str_name = (char*)malloc(str_name_len + 1);
            if (str_name != NULL) {
                memcpy(str_name, data + offset, str_name_len);
                str_name[str_name_len] = '\0';
                
                // Use part of the remaining data as string value
                size_t remaining_size = size - offset - str_name_len;
                if (remaining_size > 0) {
                    size_t str_val_len = (remaining_size > 100) ? 100 : remaining_size; // Limit string length
                    char* str_val = (char*)malloc(str_val_len + 1);
                    if (str_val != NULL) {
                        memcpy(str_val, data + offset + str_name_len, str_val_len);
                        str_val[str_val_len] = '\0';
                        
                        // Add string to object
                        cJSON* string_item = cJSON_AddStringToObject(root_obj, str_name, str_val);
                        if (string_item != NULL) {
                            // Successfully added string item
                        }
                        
                        free(str_val);
                    }
                }
                
                free(str_name);
            }
            
            offset += str_name_len;
        }
    }

    // Extract a name for the nested object
    if (offset + sizeof(uint32_t) <= size) {
        uint32_t obj_name_len = *(uint32_t*)(data + offset);
        offset += sizeof(uint32_t);
        
        if (obj_name_len > 0 && offset + obj_name_len <= size) {
            char* obj_name = (char*)malloc(obj_name_len + 1);
            if (obj_name != NULL) {
                memcpy(obj_name, data + offset, obj_name_len);
                obj_name[obj_name_len] = '\0';
                
                // Add object to object
                cJSON* nested_obj = cJSON_AddObjectToObject(root_obj, obj_name);
                if (nested_obj != NULL) {
                    // Add some content to the nested object
                    if (offset + obj_name_len + 4 <= size) {  // Ensure we have more data
                        double nested_num = *(double*)(data + offset + obj_name_len);
                        cJSON_AddNumberToObject(nested_obj, "nested_number", nested_num);
                    }
                }
                
                free(obj_name);
            }
            
            offset += obj_name_len;
        }
    }

    // Extract a name for the array
    if (offset + sizeof(uint32_t) <= size) {
        uint32_t arr_name_len = *(uint32_t*)(data + offset);
        offset += sizeof(uint32_t);
        
        if (arr_name_len > 0 && offset + arr_name_len <= size) {
            char* arr_name = (char*)malloc(arr_name_len + 1);
            if (arr_name != NULL) {
                memcpy(arr_name, data + offset, arr_name_len);
                arr_name[arr_name_len] = '\0';
                
                // Add array to object
                cJSON* array_obj = cJSON_AddArrayToObject(root_obj, arr_name);
                if (array_obj != NULL) {
                    // Add some items to the array if possible
                    if (offset + arr_name_len + 8 <= size) {
                        double arr_val = *(double*)(data + offset + arr_name_len);
                        cJSON* arr_item = cJSON_CreateNumber(arr_val);
                        if (arr_item != NULL) {
                            cJSON_AddItemToArray(array_obj, arr_item);
                        }
                    }
                }
                
                free(arr_name);
            }
            
            offset += arr_name_len;
        }
    }

    // Test cJSON_AddItemToObject with a newly created item
    if (offset + sizeof(uint32_t) <= size && offset + sizeof(uint32_t) + 4 <= size) {
        uint32_t add_item_name_len = *(uint32_t*)(data + offset);
        offset += sizeof(uint32_t);
        
        if (add_item_name_len > 0 && offset + add_item_name_len <= size) {
            char* add_item_name = (char*)malloc(add_item_name_len + 1);
            if (add_item_name != NULL) {
                memcpy(add_item_name, data + offset, add_item_name_len);
                add_item_name[add_item_name_len] = '\0';
                
                // Create a new item to add
                double val_for_add_item = *(double*)(data + offset + add_item_name_len);
                cJSON* new_item = cJSON_CreateNumber(val_for_add_item);
                
                if (new_item != NULL) {
                    int result = cJSON_AddItemToObject(root_obj, add_item_name, new_item);
                    if (result == 0) {
                        // On failure, manually delete the item since it wasn't added
                        cJSON_Delete(new_item);
                    }
                }
                
                free(add_item_name);
            }
            
            offset += add_item_name_len;
        }
    }

    // Clean up the entire JSON object tree
    cJSON_Delete(root_obj);

    return 0;
}
