#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing c-ares library APIs
// This driver tests the following APIs: ares_init, ares_library_cleanup, 
// ares_init_options, ares_library_init, ares_destroy

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize library first
    int lib_init_result = ares_library_init(ARES_LIB_INIT_ALL);
    
    // Extract data for different operations based on size
    if (size < sizeof(int) * 2) {
        // If not enough data, just cleanup and return
        if (lib_init_result == ARES_SUCCESS) {
            ares_library_cleanup();
        }
        return 0;
    }
    
    // Use first portion of data as flags for library init
    int flags = 0;
    if (size >= sizeof(int)) {
        memcpy(&flags, data, sizeof(int));
        // Only use lower bits to ensure valid flags - removed ARES_LIB_INIT_ANDROID which may not exist
        flags &= ARES_LIB_INIT_WIN32; // Only include WIN32 flag if available
    }
    
    // Use second portion for option mask
    int optmask = 0;
    if (size >= sizeof(int) * 2) {
        memcpy(&optmask, data + sizeof(int), sizeof(int));
        // Mask to valid option bits - removed unsupported options that don't exist in this version
        optmask &= (ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES |
                   ARES_OPT_NDOTS | ARES_OPT_UDP_PORT | ARES_OPT_TCP_PORT |
                   ARES_OPT_SERVERS | ARES_OPT_SOCK_STATE_CB |
                   ARES_OPT_SORTLIST | ARES_OPT_DOMAINS |
                   ARES_OPT_LOOKUPS | ARES_OPT_ROTATE |
                   ARES_OPT_EDNSPSZ | ARES_OPT_RESOLVCONF);
    }
    
    ares_channel channel1 = NULL;
    ares_channel channel2 = NULL;
    struct ares_options options;
    int result;
    
    // Test ares_init
    result = ares_init(&channel1);
    if (result == ARES_SUCCESS && channel1 != NULL) {
        // Test ares_destroy
        ares_destroy(channel1);
        channel1 = NULL;
    }
    
    // Test ares_init_options with custom options if sufficient data exists
    if (size >= sizeof(int) * 3) {
        int temp_flags;
        memcpy(&temp_flags, data + sizeof(int) * 2, sizeof(int));
        
        // Prepare options structure based on input data
        memset(&options, 0, sizeof(options));
        options.flags = temp_flags & 0xFF; // Limit to valid flag range
        options.timeout = abs(temp_flags) % 10000 + 1; // Between 1-10000 ms
        options.tries = (abs(temp_flags) % 10) + 1; // Between 1-10
        options.ndots = (abs(temp_flags) % 10); // Between 0-9
        
        result = ares_init_options(&channel2, &options, optmask);
        if (result == ARES_SUCCESS && channel2 != NULL) {
            // Test ares_destroy
            ares_destroy(channel2);
            channel2 = NULL;
        }
    }
    
    // Try another ares_init after possible previous destructions
    ares_channel channel3 = NULL;
    result = ares_init(&channel3);
    if (result == ARES_SUCCESS && channel3 != NULL) {
        ares_destroy(channel3);
        channel3 = NULL;
    }
    
    // Cleanup library
    ares_library_cleanup();
    
    // Additional call to cleanup (should handle gracefully)
    ares_library_cleanup();
    
    return 0;
}
