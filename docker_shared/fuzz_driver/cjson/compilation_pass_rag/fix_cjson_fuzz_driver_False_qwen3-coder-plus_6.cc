#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation to test cJSON APIs
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 10) {
        return 0;
    }

    // Initialize variables
    cJSON *obj1 = NULL;
    cJSON *obj2 = NULL;
    char *printed_json = NULL;
    
    // Extract lengths from input data for various operations
    size_t name_len = data[0] % 10; // Limit name length to reasonable size
    if (name_len == 0) name_len = 1;
    if (name_len > size - 1) name_len = size - 1;
    
    size_t second_name_len = data[1] % 10;
    if (second_name_len == 0) second_name_len = 1;
    if (second_name_len > size - name_len - 1) second_name_len = size - name_len - 1;
    
    // Create first JSON object
    obj1 = cJSON_CreateObject();
    if (obj1 == NULL) {
        return 0;
    }
    
    // Create second JSON object
    obj2 = cJSON_CreateObject();
    if (obj2 == NULL) {
        cJSON_Delete(obj1);
        return 0;
    }
    
    // Create name for first null field from input data
    char *name1 = (char*)malloc(name_len + 1);
    if (name1 != NULL) {
        memcpy(name1, data + 2, name_len);
        name1[name_len] = '\0';
        
        // Add null value to first object
        cJSON *null_field1 = cJSON_AddNullToObject(obj1, name1);
        if (null_field1 == NULL) {
            // Even if failed, continue testing other operations
        }
        free(name1);
    }
    
    // Create name for second null field from input data
    char *name2 = (char*)malloc(second_name_len + 1);
    if (name2 != NULL) {
        memcpy(name2, data + 2 + name_len, second_name_len);
        name2[second_name_len] = '\0';
        
        // Add null value to second object
        cJSON *null_field2 = cJSON_AddNullToObject(obj2, name2);
        if (null_field2 == NULL) {
            // Even if failed, continue testing other operations
        }
        free(name2);
    }
    
    // Compare the two objects (they should be different unless both have same null fields)
    cJSON_bool are_equal = cJSON_Compare(obj1, obj2, 1); // Case sensitive comparison
    
    // Test printing first object with buffered approach
    int prebuffer_size = 256; // Reasonable default buffer size
    printed_json = cJSON_PrintBuffered(obj1, prebuffer_size, 1); // Formatted output
    
    if (printed_json != NULL) {
        // Free the printed JSON string - Fixed: replaced global_hooks.deallocate with free()
        free(printed_json);
        printed_json = NULL;
    }
    
    // Test printing second object with buffered approach
    printed_json = cJSON_PrintBuffered(obj2, prebuffer_size, 0); // Unformatted output
    
    if (printed_json != NULL) {
        // Free the printed JSON string - Fixed: replaced global_hooks.deallocate with free()
        free(printed_json);
        printed_json = NULL;
    }
    
    // Clean up allocated objects
    cJSON_Delete(obj1);
    cJSON_Delete(obj2);
    
    return 0;
}
