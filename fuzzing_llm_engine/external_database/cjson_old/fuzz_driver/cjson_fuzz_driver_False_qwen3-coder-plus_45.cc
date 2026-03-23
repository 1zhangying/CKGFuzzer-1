#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test cJSON APIs: cJSON_IsInvalid, cJSON_IsString, cJSON_CreateString, cJSON_IsRaw, cJSON_CreateRaw
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cJSON* string_item = NULL;
    cJSON* raw_item = NULL;
    
    // Early exit if size is too small to work with
    if (size < 2) {
        return 0;
    }
    
    // Divide input data into two parts for string and raw
    size_t half_size = size / 2;
    
    // Create null-terminated strings from input data
    char* string_input = (char*)malloc(half_size + 1);
    char* raw_input = (char*)malloc((size - half_size) + 1);
    
    if (!string_input || !raw_input) {
        free(string_input);
        free(raw_input);
        return 0;
    }
    
    memcpy(string_input, data, half_size);
    string_input[half_size] = '\0';
    
    memcpy(raw_input, data + half_size, size - half_size);
    raw_input[size - half_size] = '\0';
    
    // Test cJSON_CreateString
    string_item = cJSON_CreateString(string_input);
    
    // Test cJSON_IsString with the created string item
    if (string_item != NULL) {
        bool is_string = cJSON_IsString(string_item);
        
        // Test cJSON_IsInvalid with the string item (should return false)
        bool is_invalid = cJSON_IsInvalid(string_item);
        
        // Clean up the string item
        cJSON_Delete(string_item);
        string_item = NULL;
    }
    
    // Test cJSON_CreateRaw
    raw_item = cJSON_CreateRaw(raw_input);
    
    // Test cJSON_IsRaw with the created raw item
    if (raw_item != NULL) {
        bool is_raw = cJSON_IsRaw(raw_item);
        
        // Test cJSON_IsInvalid with the raw item (should return false)
        bool is_invalid = cJSON_IsInvalid(raw_item);
        
        // Clean up the raw item
        cJSON_Delete(raw_item);
        raw_item = NULL;
    }
    
    // Test with NULL inputs to check for robustness
    bool null_is_string = cJSON_IsString(NULL);
    bool null_is_raw = cJSON_IsRaw(NULL);
    bool null_is_invalid = cJSON_IsInvalid(NULL);
    
    // Test creating items with empty strings
    cJSON* empty_string_item = cJSON_CreateString("");
    if (empty_string_item != NULL) {
        cJSON_Delete(empty_string_item);
    }
    
    cJSON* empty_raw_item = cJSON_CreateRaw("");
    if (empty_raw_item != NULL) {
        cJSON_Delete(empty_raw_item);
    }
    
    // Free allocated memory
    free(string_input);
    free(raw_input);
    
    return 0;
}
