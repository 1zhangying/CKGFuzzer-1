#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for c-ares library APIs
// Tests: ares_init, ares_library_cleanup, ares_init_options, ares_library_cleanup, ares_destroy

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize library first
    int lib_init_result = ares_library_init(ARES_LIB_INIT_ALL);
    if (lib_init_result != ARES_SUCCESS) {
        // If library init fails, still try to cleanup just in case
        ares_library_cleanup();
        return 0;
    }

    // Extract initial option mask from input data
    int optmask = 0;
    if (size >= sizeof(int)) {
        // Copy the first 4 bytes as optmask
        memcpy(&optmask, data, sizeof(int));
        data += sizeof(int);
        size -= sizeof(int);
    }

    ares_channel channel1 = nullptr;
    ares_channel channel2 = nullptr;
    
    // Test ares_init - basic initialization
    int result1 = ares_init(&channel1);
    if (result1 == ARES_SUCCESS && channel1 != nullptr) {
        // Test ares_destroy to clean up
        ares_destroy(channel1);
        channel1 = nullptr;
    }

    // Test ares_init_options with custom options if there's enough data
    if (size >= sizeof(struct ares_options)) {
        struct ares_options options;
        // Copy available data to options structure
        size_t copy_size = (sizeof(struct ares_options) < size) ? 
                           sizeof(struct ares_options) : size;
        memcpy(&options, data, copy_size);
        
        int result2 = ares_init_options(&channel2, &options, optmask);
        if (result2 == ARES_SUCCESS && channel2 != nullptr) {
            // Test ares_destroy to clean up
            ares_destroy(channel2);
            channel2 = nullptr;
        }
        
        // Update data pointer and size after using some bytes
        data += copy_size;
        size -= copy_size;
    } else {
        // If not enough data for options, try with null options
        int result2 = ares_init_options(&channel2, nullptr, 0);
        if (result2 == ARES_SUCCESS && channel2 != nullptr) {
            // Test ares_destroy to clean up
            ares_destroy(channel2);
            channel2 = nullptr;
        }
    }

    // Additional test: Try initializing again with different flags
    if (size >= sizeof(int)) {
        int additional_flags;
        memcpy(&additional_flags, data, sizeof(int));
        ares_channel temp_channel = nullptr;
        
        // Use the extracted flags as optmask for another init attempt
        int result3 = ares_init_options(&temp_channel, nullptr, additional_flags);
        if (result3 == ARES_SUCCESS && temp_channel != nullptr) {
            ares_destroy(temp_channel);
        }
    }

    // Perform final cleanup
    ares_library_cleanup();

    return 0;
}
