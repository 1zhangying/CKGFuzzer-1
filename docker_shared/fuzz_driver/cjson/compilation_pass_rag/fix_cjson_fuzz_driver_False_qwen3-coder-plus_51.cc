#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library APIs
// Tests: cJSON_ParseWithLengthOpts, cJSON_Duplicate, cJSON_GetObjectItemCaseSensitive, cJSON_Compare, cJSON_DeleteItemFromObject

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be meaningful JSON
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated copy of the input data for parsing
    char *json_string = (char *)malloc(size + 1);
    if (!json_string) {
        return 0; // Allocation failed
    }
    
    memcpy(json_string, data, size);
    json_string[size] = '\0';

    // Variables for API usage
    cJSON *parsed_json = NULL;
    cJSON *duplicated_json = NULL;
    cJSON *item_from_original = NULL;
    cJSON *item_from_duplicate = NULL;
    cJSON_bool comparison_result = (cJSON_bool)0;  // Use explicit cast instead of cJSON_false
    const char *parse_end = NULL;

    // Parse the JSON string with length options - using integer literal instead of cJSON_false constant
    parsed_json = cJSON_ParseWithLengthOpts(json_string, size, &parse_end, (cJSON_bool)0);
    
    if (parsed_json != NULL) {
        // Duplicate the parsed JSON structure - using integer literal instead of cJSON_true constant
        duplicated_json = cJSON_Duplicate(parsed_json, (cJSON_bool)1);
        
        if (duplicated_json != NULL) {
            // Compare the original and duplicated JSON structures - using integer literal instead of cJSON_true constant
            comparison_result = cJSON_Compare(parsed_json, duplicated_json, (cJSON_bool)1);
            
            // If the JSON is an object, try to retrieve items by key
            if (parsed_json->type == cJSON_Object) {
                // Look for some common keys to test retrieval
                const char *test_keys[] = {"key", "name", "value", "data", "id", "type"};
                int num_keys = sizeof(test_keys) / sizeof(test_keys[0]);
                
                for (int i = 0; i < num_keys; i++) {
                    // Get item from original
                    item_from_original = cJSON_GetObjectItemCaseSensitive(parsed_json, test_keys[i]);
                    
                    // Get same item from duplicate
                    if (duplicated_json->type == cJSON_Object) {
                        item_from_duplicate = cJSON_GetObjectItemCaseSensitive(duplicated_json, test_keys[i]);
                        
                        // If both exist, compare them - using integer literal instead of cJSON_true constant
                        if (item_from_original != NULL && item_from_duplicate != NULL) {
                            cJSON_Compare(item_from_original, item_from_duplicate, (cJSON_bool)1);
                        }
                        
                        // Test deletion from duplicate (only if it exists in duplicate)
                        if (item_from_duplicate != NULL) {
                            // We'll make a temporary copy to delete from
                            // Note: deleting from the duplicate would modify it, so we don't do that here
                            // Instead, we just test the deletion function with a separate object
                        }
                    }
                }
            }
            
            // Test deletion on the duplicate if it's an object
            if (duplicated_json->type == cJSON_Object) {
                // Try to delete a field from the duplicated JSON (if it exists)
                // First, get an item to delete (using first child if available)
                if (duplicated_json->child != NULL && duplicated_json->child->string != NULL) {
                    // Make a copy of the string name for deletion operation
                    char *delete_key = strdup(duplicated_json->child->string);
                    if (delete_key != NULL) {
                        // Create a temporary object for deletion test (to not affect our main duplicate)
                        cJSON *temp_obj = cJSON_Duplicate(parsed_json, (cJSON_bool)1);  // Using integer literal instead of cJSON_true constant
                        if (temp_obj != NULL && temp_obj->type == cJSON_Object) {
                            // Attempt to delete the item from temp object
                            cJSON_DeleteItemFromObject(temp_obj, delete_key);
                        }
                        if (temp_obj) {
                            cJSON_Delete(temp_obj);
                        }
                        free(delete_key);
                    }
                }
            }
        }
        
        // Clean up duplicated JSON
        if (duplicated_json) {
            cJSON_Delete(duplicated_json);
        }
    }
    
    // Clean up parsed JSON
    if (parsed_json) {
        cJSON_Delete(parsed_json);
    }
    
    // Free allocated memory
    free(json_string);
    
    return 0;
}
