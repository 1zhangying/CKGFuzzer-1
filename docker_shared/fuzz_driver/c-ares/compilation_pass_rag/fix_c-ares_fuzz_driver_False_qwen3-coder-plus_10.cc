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
// This driver tests ares_library_init, ares_init, ares_process, and ares_destroy
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize library with different flag combinations based on input
    int flags_input = 0;
    if (size >= sizeof(int)) {
        memcpy(&flags_input, data, sizeof(int));
        data += sizeof(int);
        size -= sizeof(int);
    }

    // Limit the flags to reasonable values to avoid invalid initialization
    // Removed ARES_LIB_INIT_OWN_THREADED_MUTEX as it's not defined in c-ares
    flags_input &= ARES_LIB_INIT_WIN32;

    int result = ares_library_init(flags_input);
    if (result != ARES_SUCCESS) {
        // If library init fails, try without special flags
        result = ares_library_init(0);
        if (result != ARES_SUCCESS) {
            return 0;
        }
    }

    ares_channel channel = nullptr;
    
    // Try to initialize the channel
    result = ares_init(&channel);
    if (result != ARES_SUCCESS || channel == nullptr) {
        ares_library_cleanup();
        return 0;
    }

    // Prepare FD sets for ares_process call
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    // Based on remaining input data, populate FD sets
    if (size >= sizeof(fd_mask) * 2) {
        // Extract some bytes to determine which FDs to set
        const unsigned char* byte_ptr = reinterpret_cast<const unsigned char*>(data);
        
        // Set some file descriptors based on input data
        int fd1 = byte_ptr[0] % 32;  // Keep within reasonable range
        int fd2 = byte_ptr[1] % 32;  // Keep within reasonable range
        
        if (fd1 > 0) {
            FD_SET(fd1, &read_fds);
        }
        if (fd2 > 0) {
            FD_SET(fd2, &write_fds);
        }
        
        // Advance data pointer and decrease size
        size_t bytes_used = sizeof(unsigned char) * 2;
        if (size >= bytes_used) {
            data += bytes_used;
            size -= bytes_used;
        } else {
            size = 0;
        }
    }

    // Call ares_process with prepared FD sets
    ares_process(channel, &read_fds, &write_fds);

    // Clean up resources
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}
