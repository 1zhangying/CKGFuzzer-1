#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for c-ares library APIs
// This driver tests ares_init, ares_parse_a_reply, ares_destroy, ares_query, and ares_process
// with various inputs to achieve good code coverage while maintaining safety

// Callback function for ares_query
static void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // This callback does nothing in the fuzzing context
    // In real usage, this would handle the DNS query result
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    ares_channel channel;
    int status;
    
    // Initialize the ares channel
    status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        // If initialization fails, return early
        return 0;
    }

    // Prepare data for ares_parse_a_reply testing
    // We'll try to parse the input as if it were a DNS reply
    if (size > sizeof(int)) {  // Need at least size for length parameter
        int reply_len = *(int*)data % size;  // Use first 4 bytes as length, constrained by actual size
        if (reply_len >= 0 && reply_len <= (int)(size - sizeof(int))) {
            const unsigned char *reply_data = data + sizeof(int);
            
            // Try to parse the reply as an A record response
            struct hostent *host = NULL;
            struct ares_addrttl addrttls[10];  // Limit to 10 records to prevent excessive allocation
            int naddrttls = 10;
            
            status = ares_parse_a_reply(reply_data, reply_len, &host, addrttls, &naddrttls);
            
            // Free the hostent structure if it was created
            if (host) {
                // Free the hostent structure properly
                if (host->h_name) ares_free(host->h_name);
                if (host->h_aliases) {
                    char **alias = host->h_aliases;
                    while (*alias) {
                        ares_free(*alias);
                        alias++;
                    }
                    ares_free(host->h_aliases);
                }
                if (host->h_addr_list) {
                    char **addr = host->h_addr_list;
                    while (*addr) {
                        ares_free(*addr);
                        addr++;
                    }
                    ares_free(host->h_addr_list);
                }
            }
        }
    }

    // Test ares_query with a crafted hostname
    // Extract a hostname from the remaining data
    if (size > sizeof(int) + 1) {
        size_t offset = sizeof(int);
        size_t hostname_len = data[offset] % (size - offset - 1);  // Length of hostname
        if (hostname_len > 0 && offset + 1 + hostname_len <= size) {
            char *hostname = (char *)malloc(hostname_len + 1);
            if (hostname) {
                memcpy(hostname, data + offset + 1, hostname_len);
                hostname[hostname_len] = '\0';  // Null terminate
                
                // Perform a DNS query
                ares_query(channel, hostname, C_IN, T_A, query_callback, NULL);
                
                // Clean up hostname
                free(hostname);
            }
        }
    }

    // Test ares_process with empty fd_sets
    // In a real application, this would process file descriptor sets
    // For fuzzing, we just call it with empty sets
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    
    ares_process(channel, &read_fds, &write_fds);

    // Clean up the channel
    ares_destroy(channel);
    
    return 0;
}
