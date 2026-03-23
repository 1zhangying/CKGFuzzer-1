#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Global channel for the fuzzer
static ares_channel channel = nullptr;

// Structure to hold query data for callbacks
struct QueryData {
    uint8_t *buffer;
    size_t size;
};

// Callback function for DNS queries
static void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // In fuzzing context, we just need to handle the callback safely
    // Don't do anything that might cause side effects
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)abuf;
    (void)alen;
}

// Cleanup function to properly destroy the channel
static void cleanup() {
    if (channel) {
        ares_destroy(channel);
        channel = nullptr;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0; // Not enough data for meaningful fuzzing
    }

    // Initialize library only once per run if not already done
    if (!channel) {
        if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
            return 0;
        }
        
        if (ares_init(&channel) != ARES_SUCCESS) {
            ares_library_cleanup();
            return 0;
        }
    }

    // Create local copies of data for manipulation
    uint8_t *local_data = (uint8_t*)malloc(size);
    if (!local_data) {
        return 0;
    }
    memcpy(local_data, data, size);

    // Use part of the input to determine which API to call
    size_t offset = 0;
    
    // Test ares_query - needs a domain name from input
    if (size > 10) {
        // Extract a potential domain name from input
        size_t name_len = local_data[offset] % 10; // Limit name length
        if (name_len == 0) name_len = 1;
        offset++;
        
        if (offset + name_len <= size) {
            char *domain_name = (char*)malloc(name_len + 1);
            if (domain_name) {
                memcpy(domain_name, local_data + offset, name_len);
                domain_name[name_len] = '\0';
                
                // Ensure domain name is valid ASCII and doesn't contain control chars
                for (size_t i = 0; i < name_len; i++) {
                    if (domain_name[i] < 32 || domain_name[i] > 126) {
                        domain_name[i] = 'a'; // Replace with safe character
                    }
                }
                
                // Call ares_query with extracted domain name
                ares_query(channel, domain_name, C_IN, T_A, query_callback, nullptr);
                
                free(domain_name);
            }
            offset += name_len;
        }
    }

    // Test ares_send - needs a valid DNS query buffer
    if (size > offset + HFIXEDSZ) {  // HFIXEDSZ is header fixed size (normally 12 bytes)
        int qlen = size - offset;
        if (qlen > HFIXEDSZ && qlen < (1 << 16)) {  // Valid query length
            ares_send(channel, local_data + offset, qlen, query_callback, nullptr);
        }
    }

    // Test ares_process - requires fd_sets
    if (size > offset + 2 * sizeof(fd_set)) {
        // Create fd_sets based on input data
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        
        // Set some bits based on input data
        for (size_t i = offset; i < size && (i - offset) < sizeof(fd_set); i++) {
            if (local_data[i] % 2) {
                int fd = local_data[i] % FD_SETSIZE;
                FD_SET(fd, &read_fds);
            } else {
                int fd = local_data[i] % FD_SETSIZE;
                FD_SET(fd, &write_fds);
            }
        }
        
        // Process the file descriptors
        ares_process(channel, &read_fds, &write_fds);
    }

    // Test ares_process_fd - requires socket file descriptors
    if (size > offset + 2 * sizeof(ares_socket_t)) {
        // Use input bytes to create file descriptor values
        ares_socket_t read_fd = ARES_SOCKET_BAD;  // Default value
        ares_socket_t write_fd = ARES_SOCKET_BAD; // Default value
        
        if (offset + 2 <= size) {
            read_fd = (ares_socket_t)(local_data[offset] % 1024);  // Limit to reasonable range
            write_fd = (ares_socket_t)(local_data[offset + 1] % 1024);
            
            // Process specific file descriptors
            ares_process_fd(channel, read_fd, write_fd);
        }
    }

    // Clean up allocated memory
    free(local_data);
    
    // Note: We don't destroy the channel here since this is a fuzzer
    // that may be called repeatedly. Instead, rely on process exit to clean up.
    
    return 0;
}
