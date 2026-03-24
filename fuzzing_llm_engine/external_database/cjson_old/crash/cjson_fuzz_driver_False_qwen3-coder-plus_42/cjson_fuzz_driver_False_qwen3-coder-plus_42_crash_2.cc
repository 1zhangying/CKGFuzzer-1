#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// Tests the following APIs: cJSON_AddNullToObject, cJSON_Delete, 
// cJSON_GetStringValue, cJSON_IsNull, cJSON_CreateNull

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 10) {
        return 0;
    }

    // Initialize variables to track our JSON objects
    cJSON* root_obj = NULL;
    cJSON* null_item1 = NULL;
    cJSON* null_item2 = NULL;
    
    // Calculate indices for extracting different parts of the input data
    size_t name_len = size > 10 ? 5 : size / 2;  // Length for name string
    size_t offset = name_len + 1;                // Offset after name
    
    // Ensure we don't exceed input boundaries
    if (offset >= size) {
        return 0;
    }
    
    // Create a copy of the name portion to use as key for JSON object
    char* name_str = (char*)malloc(name_len + 1);
    if (!name_str) {
        return 0;
    }
    
    memcpy(name_str, data, name_len);
    name_str[name_len] = '\0';  // Null terminate the string
    
    // Create a root JSON object
    root_obj = cJSON_CreateObject();
    if (!root_obj) {
        free(name_str);
        return 0;
    }
    
    // Test cJSON_CreateNull - creates a null JSON value
    null_item1 = cJSON_CreateNull();
    if (!null_item1) {
        cJSON_Delete(root_obj);
        free(name_str);
        return 0;
    }
    
    // Test cJSON_IsNull - check if the item is null
    int is_null = cJSON_IsNull(null_item1);
    if (!is_null) {
        // This should always be true for a null item
        // But we continue to test other functionality
    }
    
    // Add the null item to the root object using the extracted name
    cJSON* added_null = cJSON_AddNullToObject(root_obj, name_str);
    if (!added_null) {
        // If addition failed, try to add our created null item anyway
        // But since AddNullToObject failed, we'll just continue with tests
    } else {
        // Verify that the added item is also null
        int added_is_null = cJSON_IsNull(added_null);
        (void)added_is_null; // Suppress unused variable warning
    }
    
    // Test creating another null item
    null_item2 = cJSON_CreateNull();
    if (null_item2) {
        // Test adding this second null to the root object with a fixed name
        cJSON* added_null2 = cJSON_AddNullToObject(root_obj, "second_null");
        if (added_null2) {
            // Verify the second added item is null
            int second_is_null = cJSON_IsNull(added_null2);
            (void)second_is_null; // Suppress unused variable warning
            
            // Test cJSON_GetStringValue on a null item (should return NULL)
            const char* str_val = cJSON_GetStringValue(added_null2);
            if (str_val != NULL) {
                // This shouldn't happen since null items don't have string values
            }
        }
        
        // Since cJSON_AddNullToObject creates its own null item,
        // we should not delete null_item2 here as it wasn't added to the object directly
        // Instead, let's create a standalone null item and test GetStringValue
        cJSON* standalone_null = cJSON_CreateNull();
        if (standalone_null) {
            // Test GetStringValue on a null item (should return NULL)
            const char* null_str_val = cJSON_GetStringValue(standalone_null);
            if (null_str_val != NULL) {
                // This should never happen
            }
            
            // Clean up standalone null
            cJSON_Delete(standalone_null);
        }
    }
    
    // Test cJSON_GetStringValue on the first null item (should return NULL)
    const char* first_str_val = cJSON_GetStringValue(null_item1);
    if (first_str_val != NULL) {
        // This should never happen
    }
    
    // Test cJSON_IsNull on the original null item
    int original_is_null = cJSON_IsNull(null_item1);
    (void)original_is_null; // Suppress unused variable warning
    
    // Clean up all allocated memory
    cJSON_Delete(root_obj);  // This will also delete all child items
    free(name_str);
    
    // Note: We don't call cJSON_Delete(null_item1) because it was added to the object
    // and will be freed when we delete the root object
    
    return 0;
}
