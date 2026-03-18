#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Callback function for ares operations
static void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // In fuzzing context, we just need to handle the callback without crashing
    // This is called when DNS query completes
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)abuf;
    (void)alen;
}

// Fuzz driver entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {  // Need at least some data to work with
        return 0;
    }

    ares_channel channel = NULL;
    int result = ares_init(&channel);
    
    if (result != ARES_SUCCESS || channel == NULL) {
        return 0;
    }

    // Set up a simple DNS query
    const char* hostname = "example.com";
    
    // Use part of the input data to determine query parameters
    int query_class = ARES_CLASS_IN;
    int query_type = ARES_REC_TYPE_A;
    
    if (size >= 1) {
        query_class = ARES_CLASS_IN + (data[0] % 10);  // Limit class variation
    }
    if (size >= 2) {
        query_type = ARES_REC_TYPE_A + (data[1] % 20);  // Limit type variation
    }
    
    // Issue a DNS query
    ares_query(channel, hostname, query_class, query_type, query_callback, NULL);

    // Prepare FD sets for ares_process
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    
    // Use more input data to set up file descriptors
    ares_socket_t read_fd = ARES_SOCKET_BAD;
    ares_socket_t write_fd = ARES_SOCKET_BAD;
    
    if (size >= 6) {
        // Use 4 bytes for read_fd and 2 bytes for write_fd
        read_fd = *(uint32_t*)(data + 2) % 1024;  // Reasonable range
        write_fd = *(uint16_t*)(data + 6) % 1024; // Reasonable range
    } else if (size >= 4) {
        read_fd = *(uint32_t*)(data + 2) % 1024;
    }

    // Call ares_process with prepared FD sets
    ares_process(channel, &read_fds, &write_fds);

    // Call ares_process_fd with specific file descriptors
    ares_process_fd(channel, read_fd, write_fd);

    // If we have enough data, try to use ares_send with raw query buffer
    if (size >= HFIXEDSZ + 2) {  // At least header size + some data
        int qlen = HFIXEDSZ + (data[0] % (size - HFIXEDSZ));  // Make sure qlen is valid
        if (qlen <= (int)(size - 2) && qlen < (1 << 16)) {  // Ensure within bounds
            ares_send(channel, data + 2, qlen, query_callback, NULL);
        }
    }

    // Clean up
    ares_destroy(channel);

    return 0;
}
