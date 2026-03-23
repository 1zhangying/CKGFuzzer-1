#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Callback function for ares_query
void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // In a fuzzing context, we just need to handle the callback without crashing
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)abuf;
    (void)alen;
}

// Fuzz driver entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize the c-ares library
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
        return 0; // Exit early if initialization fails
    }

    // Local variables for this fuzz run
    ares_channel channel = nullptr;
    struct ares_options options;
    int optmask = 0;
    
    // Zero out options structure
    memset(&options, 0, sizeof(options));
    
    // Check if we have enough data for basic operations
    if (size < sizeof(int) + 1) {  // Need at least an integer and one byte for hostname
        ares_library_cleanup();
        return 0;
    }
    
    // Extract initial parameters from fuzz data
    size_t offset = 0;
    int init_option_mask = 0;
    
    if (offset + sizeof(int) <= size) {
        memcpy(&init_option_mask, data + offset, sizeof(int));
        offset += sizeof(int);
    }
    
    // Determine which flags to use based on fuzz data
    optmask = init_option_mask & (ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | 
                                  ARES_OPT_NDOTS | ARES_OPT_UDP_PORT | ARES_OPT_TCP_PORT |
                                  ARES_OPT_SOCK_STATE_CB | ARES_OPT_SERVERS | ARES_OPT_LOOKUPS);
    
    // Set some options based on fuzz data if relevant flags are set
    if (optmask & ARES_OPT_TIMEOUTMS) {
        int timeout_ms = 0;
        if (offset + sizeof(int) <= size) {
            memcpy(&timeout_ms, data + offset, sizeof(int));
            offset += sizeof(int);
            options.timeout = abs(timeout_ms) % 10000; // Keep within reasonable range
        }
    }
    
    if (optmask & ARES_OPT_TRIES) {
        int tries = 0;
        if (offset + sizeof(int) <= size) {
            memcpy(&tries, data + offset, sizeof(int));
            offset += sizeof(int);
            options.tries = (abs(tries) % 10) + 1; // Between 1 and 10
        }
    }
    
    // Initialize the channel with options
    int result = ares_init_options(&channel, &options, optmask);
    if (result != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }
    
    // Prepare a hostname for the query from remaining fuzz data
    if (offset < size) {
        // Find a null terminator or end of data to define the hostname
        size_t hostname_len = 0;
        for (size_t i = offset; i < size && hostname_len < 255; ++i) {
            if (data[i] == '\0') break;
            hostname_len++;
        }
        
        if (hostname_len > 0) {
            char *hostname = (char*)malloc(hostname_len + 1);
            if (hostname) {
                memcpy(hostname, data + offset, hostname_len);
                hostname[hostname_len] = '\0';
                
                // Ensure hostname is a valid DNS name (alphanumeric, dots, hyphens)
                for (size_t i = 0; i < hostname_len; i++) {
                    char c = hostname[i];
                    if (!((c >= 'a' && c <= 'z') || 
                          (c >= 'A' && c <= 'Z') || 
                          (c >= '0' && c <= '9') || 
                          c == '.' || c == '-')) {
                        hostname[i] = 'x'; // Replace invalid chars
                    }
                }
                
                // Perform a DNS query (will likely fail due to lack of network in fuzzing context)
                ares_query(channel, hostname, C_IN, T_A, query_callback, nullptr);
                
                free(hostname);
            }
        }
    }
    
    // Process file descriptors - use invalid ones since we don't have real sockets in fuzzing
    ares_socket_t read_fd = ARES_SOCKET_BAD;
    ares_socket_t write_fd = ARES_SOCKET_BAD;
    
    // Extract fd values from remaining data if possible
    if (offset + 2 * sizeof(ares_socket_t) <= size) {
        ares_socket_t temp_read_fd, temp_write_fd;
        memcpy(&temp_read_fd, data + offset, sizeof(ares_socket_t));
        offset += sizeof(ares_socket_t);
        memcpy(&temp_write_fd, data + offset, sizeof(ares_socket_t));
        offset += sizeof(ares_socket_t);
        
        // Use these as potential fd values (but they'll be ignored as ARES_SOCKET_BAD)
        read_fd = (temp_read_fd < 0) ? ARES_SOCKET_BAD : temp_read_fd;
        write_fd = (temp_write_fd < 0) ? ARES_SOCKET_BAD : temp_write_fd;
    }
    
    // Process the file descriptors (this will handle any pending I/O)
    ares_process_fd(channel, read_fd, write_fd);
    
    // Clean up the channel
    ares_destroy(channel);
    
    // Clean up the library
    ares_library_cleanup();
    
    return 0;
}
