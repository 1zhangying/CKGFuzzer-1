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
// This driver tests ares_library_init, ares_init, ares_process, and ares_destroy APIs

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to work with
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize library first
    int lib_flags = 0;
    if (size >= sizeof(int)) {
        // Extract flags from input data for library initialization
        lib_flags = *(const int*)data;
        // Limit flags to reasonable values to avoid unexpected behavior
        lib_flags = lib_flags & (ARES_LIB_INIT_WIN32 | ARES_LIB_INIT_OWN_THREADED_RESOLVER);
    }
    
    int result = ares_library_init(lib_flags);
    if (result != ARES_SUCCESS) {
        // If library init fails, just return early
        return 0;
    }

    // Initialize a channel
    ares_channel channel;
    result = ares_init(&channel);
    if (result != ARES_SUCCESS || !channel) {
        // If channel init fails, cleanup and return
        ares_library_cleanup();
        return 0;
    }

    // Prepare fd_sets for ares_process based on remaining input data
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    
    // Use additional input data to determine which file descriptors to set
    if (size > sizeof(int)) {
        const uint8_t* extra_data = data + sizeof(int);
        size_t remaining_size = size - sizeof(int);
        
        // Set up to 32 possible file descriptors based on input bytes
        for (size_t i = 0; i < remaining_size && i < 32; ++i) {
            int fd = extra_data[i] % 32; // Keep fd in reasonable range
            if ((extra_data[i] % 2) == 0) {  // Even numbers go to read_fds
                FD_SET(fd, &read_fds);
            } else {  // Odd numbers go to write_fds
                FD_SET(fd, &write_fds);
            }
        }
    }

    // Call ares_process with the prepared fd_sets
    ares_process(channel, &read_fds, &write_fds);

    // Clean up resources
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}
