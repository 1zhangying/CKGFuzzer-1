#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON boolean-related APIs
// This fuzz driver tests the following APIs:
// - cJSON_IsBool
// - cJSON_IsTrue
// - cJSON_GetNumberValue
// - cJSON_IsFalse
// - cJSON_CreateBool
// - cJSON_CreateTrue

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size < 1) {
        return 0;
    }

    // Use first byte to determine which operation to perform
    uint8_t op_selector = data[0];
    size_t remaining_size = size > 0 ? size - 1 : 0;
    const uint8_t *remaining_data = size > 0 ? data + 1 : data;

    // Create different types of cJSON items based on input
    cJSON *item = NULL;
    
    // Operation selection based on first byte
    switch (op_selector % 6) {
        case 0:
            // Create a boolean item based on second byte
            if (remaining_size > 0) {
                item = cJSON_CreateBool(remaining_data[0] % 2); // true if even, false if odd
            } else {
                item = cJSON_CreateBool(0); // default to false
            }
            break;
            
        case 1:
            // Create a true item
            item = cJSON_CreateTrue();
            break;
            
        case 2:
            // Create a number item since we'll test cJSON_GetNumberValue
            if (remaining_size >= sizeof(double)) {
                double num_value;
                memcpy(&num_value, remaining_data, sizeof(double));
                item = cJSON_CreateNumber(num_value);
            } else {
                item = cJSON_CreateNumber(0.0);
            }
            break;
            
        case 3:
            // Create a string item to test non-boolean behavior
            if (remaining_size > 0) {
                size_t str_len = remaining_size > 10 ? 10 : remaining_size; // limit string length
                char *str = (char*)malloc(str_len + 1);
                if (str) {
                    memcpy(str, remaining_data, str_len);
                    str[str_len] = '\0';
                    item = cJSON_CreateString(str);
                    free(str);
                }
            } else {
                item = cJSON_CreateString("test");
            }
            break;
            
        case 4:
            // Create a null item
            item = cJSON_CreateNull();
            break;
            
        case 5:
            // Create an array item
            item = cJSON_CreateArray();
            break;
    }

    // Test cJSON_IsBool
    if (item != NULL) {
        cJSON_bool is_bool = cJSON_IsBool(item);
        // Use the result (prevent compiler optimization)
        (void)is_bool;
    }

    // Test cJSON_IsTrue
    if (item != NULL) {
        cJSON_bool is_true = cJSON_IsTrue(item);
        // Use the result (prevent compiler optimization)
        (void)is_true;
    }

    // Test cJSON_IsFalse
    if (item != NULL) {
        cJSON_bool is_false = cJSON_IsFalse(item);
        // Use the result (prevent compiler optimization)
        (void)is_false;
    }

    // Test cJSON_GetNumberValue
    if (item != NULL) {
        double num_val = cJSON_GetNumberValue(item);
        // Use the result (prevent compiler optimization)
        (void)num_val;
    }

    // Additional testing with created items
    // Test creating boolean values with various inputs
    for (int i = 0; i < 2 && (i + 1) < remaining_size; i++) {
        cJSON *temp_bool = cJSON_CreateBool(remaining_data[i] % 2);
        if (temp_bool != NULL) {
            // Test all boolean checks on this item
            cJSON_bool check_bool = cJSON_IsBool(temp_bool);
            cJSON_bool check_true = cJSON_IsTrue(temp_bool);
            cJSON_bool check_false = cJSON_IsFalse(temp_bool);
            double num_value = cJSON_GetNumberValue(temp_bool);
            
            // Use results to prevent optimization
            (void)check_bool;
            (void)check_true;
            (void)check_false;
            (void)num_value;
            
            cJSON_Delete(temp_bool);
        }
    }

    // Create a true item and test it
    cJSON *true_item = cJSON_CreateTrue();
    if (true_item != NULL) {
        cJSON_bool is_bool = cJSON_IsBool(true_item);
        cJSON_bool is_true = cJSON_IsTrue(true_item);
        cJSON_bool is_false = cJSON_IsFalse(true_item);
        double num_val = cJSON_GetNumberValue(true_item);
        
        // Use results to prevent optimization
        (void)is_bool;
        (void)is_true;
        (void)is_false;
        (void)num_val;
        
        cJSON_Delete(true_item);
    }

    // Clean up main item
    if (item != NULL) {
        cJSON_Delete(item);
    }

    return 0;
}
