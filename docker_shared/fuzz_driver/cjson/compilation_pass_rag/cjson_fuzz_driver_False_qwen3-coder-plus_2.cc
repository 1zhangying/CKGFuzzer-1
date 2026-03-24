#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests the following APIs:
// - cJSON_CreateObject
// - cJSON_CreateBool
// - cJSON_AddItemToObject
// - cJSON_AddBoolToObject
// - cJSON_Print
// - cJSON_Delete

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create the root JSON object
    cJSON* root_obj = cJSON_CreateObject();
    if (root_obj == NULL) {
        return 0;
    }

    // Use part of the input data to determine how many boolean items to add
    size_t offset = 0;
    
    // First, let's try to add some direct boolean values using cJSON_AddBoolToObject
    if (size >= 2) {
        // Extract a character to use as a simple key name (we'll use it modulo a small range to keep keys short)
        uint8_t key_char = data[offset];
        offset++;
        
        // Create a simple key name based on the byte value
        char key_name[10];
        snprintf(key_name, sizeof(key_name), "key%d", key_char % 10);
        
        // Use the next byte to determine boolean value
        uint8_t bool_val = data[offset];
        offset++;
        
        cJSON_bool cjson_bool = (bool_val % 2 == 0) ? cJSON_True : cJSON_False;
        
        // Add boolean to object using cJSON_AddBoolToObject
        cJSON* added_bool = cJSON_AddBoolToObject(root_obj, key_name, cjson_bool);
        if (added_bool == NULL) {
            // If adding failed, continue anyway since we still have the root object
        }
    }
    
    // Now let's create additional boolean items and add them using cJSON_AddItemToObject
    while (offset + 2 <= size) {
        // Get a character for the key name
        uint8_t key_char = data[offset];
        offset++;
        
        // Get a character for the boolean value
        uint8_t bool_val = data[offset];
        offset++;
        
        // Create a key name based on the byte value
        char key_name[10];
        snprintf(key_name, sizeof(key_name), "b%d", key_char % 100);  // Using more unique names
        
        // Create a boolean cJSON item
        cJSON_bool cjson_bool = (bool_val % 2 == 0) ? cJSON_True : cJSON_False;
        cJSON* bool_item = cJSON_CreateBool(cjson_bool);
        
        if (bool_item != NULL) {
            // Add the boolean item to the root object
            cJSON_bool add_result = cJSON_AddItemToObject(root_obj, key_name, bool_item);
            
            // If addition fails, we need to manually delete the created bool_item
            if (!add_result) {
                cJSON_Delete(bool_item);
            }
        }
    }
    
    // Try to print the JSON object to a string
    char* json_string = cJSON_Print(root_obj);
    if (json_string != NULL) {
        // Free the printed string
        free(json_string);
        json_string = NULL;
    }
    
    // Clean up the entire JSON object tree
    cJSON_Delete(root_obj);
    
    return 0;
}
