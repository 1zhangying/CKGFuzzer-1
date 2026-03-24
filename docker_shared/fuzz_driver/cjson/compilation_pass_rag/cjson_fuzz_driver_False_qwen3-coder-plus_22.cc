#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library testing
// This fuzz driver tests the following APIs:
// - cJSON_Print
// - cJSON_CreateStringArray
// - cJSON_Delete
// - cJSON_AddItemToArray
// - cJSON_CreateArray
// - cJSON_CreateString

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a copy of the input data to work with
    char* input_data = (char*)malloc(size + 1);
    if (!input_data) {
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Parse input data to determine how to construct JSON
    // We'll split the input into segments to create different parts of our JSON structure
    
    cJSON* root_array = cJSON_CreateArray();
    if (!root_array) {
        free(input_data);
        return 0;
    }

    // Create a string array using part of the input data
    // First, determine how many strings we want to create based on input size
    int num_strings = 0;
    if (size > 0) {
        num_strings = (input_data[0] % 10) + 1; // At least 1 string, max 10
    }

    if (num_strings > 0) {
        // Allocate space for string pointers
        char** string_array = (char**)malloc(num_strings * sizeof(char*));
        if (string_array) {
            size_t offset = 1; // Start after the first byte used for num_strings calculation
            
            for (int i = 0; i < num_strings; i++) {
                if (offset >= size) break;
                
                // Determine length of this string segment
                int str_len = (input_data[offset] % 10) + 1; // Length between 1-10
                offset++;
                
                if (offset + str_len > size) {
                    str_len = size - offset;
                }
                
                if (str_len <= 0) continue;
                
                // Create the string
                string_array[i] = (char*)malloc(str_len + 1);
                if (string_array[i]) {
                    memcpy(string_array[i], input_data + offset, str_len);
                    string_array[i][str_len] = '\0';
                    offset += str_len;
                } else {
                    // If allocation fails, set to empty string to maintain array integrity
                    string_array[i] = (char*)malloc(1);
                    if (string_array[i]) {
                        string_array[i][0] = '\0';
                    }
                }
            }
            
            // Create cJSON string array
            cJSON* string_array_json = cJSON_CreateStringArray((const char* const*)string_array, num_strings);
            if (string_array_json) {
                // Add the string array to the root array
                if (cJSON_AddItemToArray(root_array, string_array_json)) {
                    // Successfully added - print the result
                    char* printed_json = cJSON_Print(root_array);
                    if (printed_json) {
                        // Free the printed JSON string
                        free(printed_json);
                    }
                } else {
                    // Failed to add, delete the string array
                    cJSON_Delete(string_array_json);
                }
            }
            
            // Clean up the temporary string array
            for (int i = 0; i < num_strings; i++) {
                if (string_array[i]) {
                    free(string_array[i]);
                }
            }
            free(string_array);
        }
    }

    // Create additional string items and add them to the array
    size_t offset = 1; // Reset offset
    for (int i = 0; i < 3 && offset < size; i++) { // Create up to 3 additional string items
        int str_len = (input_data[offset] % 20) + 1; // Length between 1-20
        offset++;
        
        if (offset + str_len > size) {
            str_len = size - offset;
        }
        
        if (str_len <= 0) continue;
        
        char* temp_str = (char*)malloc(str_len + 1);
        if (temp_str) {
            memcpy(temp_str, input_data + offset, str_len);
            temp_str[str_len] = '\0';
            
            cJSON* string_item = cJSON_CreateString(temp_str);
            if (string_item) {
                if (!cJSON_AddItemToArray(root_array, string_item)) {
                    // If adding fails, delete the string item
                    cJSON_Delete(string_item);
                }
            }
            free(temp_str);
        }
        offset += str_len;
    }

    // Print the final JSON
    char* final_printed = cJSON_Print(root_array);
    if (final_printed) {
        free(final_printed);
    }

    // Clean up everything
    cJSON_Delete(root_array);
    free(input_data);

    return 0;
}
