#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for c-ares library APIs
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to work with
    if (size < 10) {
        return 0;
    }

    // Initialize c-ares channel
    ares_channel channel;
    struct ares_options options;
    int optmask = 0;
    
    int result = ares_init_options(&channel, &options, optmask);
    if (result != ARES_SUCCESS) {
        return 0;
    }

    // Extract a name string from input data for DNS query
    size_t name_len = size > 50 ? 50 : size;
    char *name = (char *)malloc(name_len + 1);
    if (!name) {
        ares_destroy(channel);
        return 0;
    }
    
    // Copy and null-terminate the name
    memcpy(name, data, name_len);
    name[name_len] = '\0';
    
    // Replace any null bytes in the middle with underscores to make valid string
    for (size_t i = 0; i < name_len; ++i) {
        if (name[i] == '\0') {
            name[i] = '_';
        }
    }

    // Step 1: Use ares_create_query to create a DNS query
    unsigned char *query_buf = NULL;
    int query_len = 0;
    unsigned short query_id = 1234; // arbitrary ID
    
    result = ares_create_query(
        name,
        C_IN,              // DNS class
        T_A,               // Query type (A record)
        query_id,          // Query ID
        1,                 // Recursion desired
        &query_buf,        // Output buffer
        &query_len,        // Output buffer length
        0                  // No EDNS
    );
    
    if (result == ARES_SUCCESS && query_buf && query_len > 0) {
        // Step 2: Use ares_send to send the query
        // Since we're fuzzing, we'll simulate sending by creating a mock callback
        // Note: In a real scenario, this would initiate actual network activity
        
        // For fuzzing purposes, we'll just validate the query creation
        // and skip the actual network call which would require a live DNS server
        
        // Step 3: Simulate receiving a response by crafting a fake response
        // This will allow us to test ares_parse_a_reply
        
        // Create a minimal fake DNS response
        // Note: This is a simplified fake response for testing purposes
        unsigned char *response_buf = (unsigned char*)malloc(query_len);
        if (response_buf) {
            memcpy(response_buf, query_buf, query_len);
            
            // Modify header to indicate response instead of query
            if (query_len >= HFIXEDSZ) {
                DNS_HEADER_SET_QR(response_buf, 1);  // Set QR bit to 1 (response)
                DNS_HEADER_SET_ANCOUNT(response_buf, 1);  // One answer
                
                // Step 4: Use ares_parse_a_reply to parse the fake response
                struct hostent *host = NULL;
                struct ares_addrttl addrttls[5];
                int naddrttls = 5;
                
                result = ares_parse_a_reply(
                    response_buf,
                    query_len,
                    &host,
                    addrttls,
                    &naddrttls
                );
                
                // If parsing was successful, free the hostent structure
                if (result == ARES_SUCCESS && host) {
                    ares_free_hostent(host);
                }
            }
            free(response_buf);
        }
        
        // Step 5: Use ares_process to process any pending I/O
        // Since we don't have actual sockets, we'll pass empty fd_sets
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        ares_process(channel, &read_fds, &write_fds);
        
        // Clean up the query buffer created by ares_create_query
        ares_free(query_buf);
    }
    
    // Clean up
    free(name);
    ares_destroy(channel);
    
    return 0;
}
