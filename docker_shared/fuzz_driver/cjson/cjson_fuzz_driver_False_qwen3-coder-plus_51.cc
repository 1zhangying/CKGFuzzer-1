#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for cJSON library APIs
// Tests: cJSON_ParseWithLengthOpts, cJSON_CreateIntArray, cJSON_AddItemToObjectCS, cJSON_PrintBuffered, cJSON_Compare

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Parse input data into different segments
    size_t json_size = size / 3;
    if (json_size == 0) {
        json_size = 1;
    }
    
    const char* json_str = reinterpret_cast<const char*>(data);
    size_t remaining_size = size - json_size;
    
    // Extract integers for array creation
    int count = 0;
    const int* numbers = nullptr;
    if (remaining_size >= sizeof(int)) {
        count = *(reinterpret_cast<const int*>(data + json_size));
        // Make sure count is positive and not too large
        if (count < 0) {
            count = -count;
        }
        if (count > 100) {
            count = 100; // Limit to prevent excessive memory allocation
        }
        
        // Calculate how many integers we can safely extract
        size_t available_ints = (remaining_size - sizeof(int)) / sizeof(int);
        if (available_ints >= static_cast<size_t>(count) && count > 0) {
            numbers = reinterpret_cast<const int*>(data + json_size + sizeof(int));
        }
    }

    // Variables for parsing results
    cJSON* parsed_json = nullptr;
    cJSON* int_array = nullptr;
    cJSON* object = nullptr;
    char* printed_result = nullptr;
    cJSON_bool result_comparison = false;

    // 1. Test cJSON_ParseWithLengthOpts
    const char* parse_end = nullptr;
    cJSON_bool require_null_terminated = (size % 2 == 0) ? 1 : 0; // Alternate based on size
    parsed_json = cJSON_ParseWithLengthOpts(json_str, json_size, &parse_end, require_null_terminated);
    
    // 2. Test cJSON_CreateIntArray
    if (numbers != nullptr && count > 0) {
        int_array = cJSON_CreateIntArray(numbers, count);
    }

    // 3. Test cJSON_AddItemToObjectCS if both objects exist
    if (parsed_json != nullptr && int_array != nullptr) {
        // Create a new object to add items to
        object = cJSON_CreateObject();
        if (object != nullptr) {
            // Add the integer array to the parsed JSON object under a test key
            if (cJSON_AddItemToObjectCS(parsed_json, "test_array", int_array)) {
                // Successfully added, so we don't delete int_array separately
                int_array = nullptr; // Ownership transferred
            }
        }
    }

    // 4. Test cJSON_PrintBuffered if we have a valid JSON object
    cJSON* target_json = parsed_json ? parsed_json : (object ? object : int_array);
    if (target_json != nullptr) {
        int prebuffer_size = (size % 1000) + 100; // Vary buffer size based on input
        printed_result = cJSON_PrintBuffered(target_json, prebuffer_size, 1); // Formatted output
    }

    // 5. Test cJSON_Compare if we have multiple JSON objects
    if (parsed_json != nullptr && object != nullptr) {
        result_comparison = cJSON_Compare(parsed_json, object, 1); // Case sensitive
    }

    // Cleanup all allocated resources
    if (parsed_json != nullptr) {
        cJSON_Delete(parsed_json);
    }
    
    // Only delete int_array if it wasn't transferred to another object
    if (int_array != nullptr) {
        cJSON_Delete(int_array);
    }
    
    if (object != nullptr) {
        cJSON_Delete(object);
    }
    
    if (printed_result != nullptr) {
        cJSON_free(printed_result);
    }

    return 0;
}
