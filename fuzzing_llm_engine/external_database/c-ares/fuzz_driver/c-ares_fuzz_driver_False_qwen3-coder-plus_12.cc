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
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize the c-ares library
    int init_result = ares_library_init(0);
    if (init_result != ARES_SUCCESS) {
        return 0;  // Early exit if library initialization fails
    }

    // Declare channel pointer
    ares_channel channel = nullptr;
    
    // Initialize ares channel
    int result = ares_init(&channel);
    if (result != ARES_SUCCESS || channel == nullptr) {
        ares_library_cleanup();
        return 0;
    }

    // Process fuzz input data to extract parameters for ares_process_fd
    if (size >= sizeof(ares_socket_t) * 2) {
        // Extract two socket file descriptors from input data
        ares_socket_t read_fd = 0;
        ares_socket_t write_fd = 0;
        
        // Copy first sizeof(ares_socket_t) bytes for read_fd
        memcpy(&read_fd, data, sizeof(ares_socket_t));
        
        // Copy next sizeof(ares_socket_t) bytes for write_fd
        memcpy(&write_fd, data + sizeof(ares_socket_t), sizeof(ares_socket_t));
        
        // Call ares_process_fd with extracted file descriptors
        ares_process_fd(channel, read_fd, write_fd);
    } else if (size >= sizeof(ares_socket_t)) {
        // If only one socket value available, use it for both read and write
        ares_socket_t fd = 0;
        memcpy(&fd, data, sizeof(ares_socket_t));
        
        // Call ares_process_fd with same fd for both read and write
        ares_process_fd(channel, fd, fd);
    } else {
        // If insufficient data, call with invalid file descriptors
        ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    }

    // Example of using ares_free_data - creating dummy data structure for testing
    // Since we don't have actual DNS reply data from this context, we'll skip complex parsing
    // But demonstrate the pattern for when we do have parsed data
    if (size > 0 && data[0] % 2 == 0) {  // Conditional execution based on input
        // In real usage, this would be populated by parsing DNS response
        // Here we just demonstrate the API call pattern
        void *dummy_data = nullptr;
        ares_free_data(dummy_data);  // Safe to call with nullptr
    }

    // Clean up the channel
    if (channel) {
        ares_destroy(channel);
    }

    // Clean up the library
    ares_library_cleanup();

    return 0;
}
