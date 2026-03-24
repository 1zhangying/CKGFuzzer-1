#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// Tests the following APIs: cJSON_AddNullToObject, cJSON_CreateObject, 
// cJSON_Compare, cJSON_PrintBuffered, cJSON_Delete

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 10) {
        return 0;
    }

    // Create first JSON object
    cJSON* obj1 = cJSON_CreateObject();
    if (obj1 == NULL) {
        return 0;
    }

    // Create second JSON object
    cJSON* obj2 = cJSON_CreateObject();
    if (obj2 == NULL) {
        cJSON_Delete(obj1);
        return 0;
    }

    // Extract name for adding null value based on input data
    size_t offset = 0;
    if (size > 2) {
        // Use first byte as length indicator for name (max 10 chars to avoid overflow)
        size_t name_len = (data[offset] % 10) + 1;
        offset++;
        
        if (offset + name_len <= size && name_len > 0) {
            // Create a name string from input data
            char* name = (char*)malloc(name_len + 1);
            if (name != NULL) {
                memcpy(name, data + offset, name_len);
                name[name_len] = '\0';
                
                // Add null value to both objects with the same name
                cJSON* null_item1 = cJSON_AddNullToObject(obj1, name);
                cJSON* null_item2 = cJSON_AddNullToObject(obj2, name);
                
                free(name);
                
                // If successful additions, try comparing them
                if (null_item1 != NULL && null_item2 != NULL) {
                    // Compare the two objects
                    cJSON_bool are_equal = cJSON_Compare(obj1, obj2, 1);
                    
                    // Print the first object to a buffered string
                    int prebuffer_size = 256; // Default buffer size
                    char* printed_str = cJSON_PrintBuffered(obj1, prebuffer_size, 1);
                    
                    if (printed_str != NULL) {
                        // Free the printed string
                        free(printed_str);
                    }
                    
                    // Print the second object to a buffered string
                    char* printed_str2 = cJSON_PrintBuffered(obj2, prebuffer_size, 1);
                    
                    if (printed_str2 != NULL) {
                        // Free the printed string
                        free(printed_str2);
                    }
                }
            }
        }
    }

    // Clean up allocated JSON objects
    cJSON_Delete(obj1);
    cJSON_Delete(obj2);

    return 0;
}
