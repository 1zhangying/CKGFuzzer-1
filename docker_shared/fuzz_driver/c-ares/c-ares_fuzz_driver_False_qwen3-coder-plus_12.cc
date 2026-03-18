#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing c-ares library functions
// This driver tests ares_init, ares_library_cleanup, ares_process, and ares_parse_aaaa_reply
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize c-ares library
    int init_result = ares_library_init(ARES_LIB_INIT_ALL);
    
    // Check if library initialization was successful
    if (init_result != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    // Initialize ares channel
    ares_channel channel;
    int channel_init_result = ares_init(&channel);
    
    if (channel_init_result != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    // Prepare file descriptor sets for ares_process
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    // Call ares_process with empty fd_sets (this is safe since we're not actually processing real sockets)
    ares_process(channel, &read_fds, &write_fds);

    // Test ares_parse_aaaa_reply if there's enough data
    if (size >= sizeof(struct dns_header)) {  // Need at least a DNS header
        struct hostent *host = NULL;
        
        // Prepare optional parameters for ares_parse_aaaa_reply
        struct ares_addr6ttl *addrttls = NULL;
        int naddrttls = 0;
        
        // First call to get the count of addresses
        int parse_result = ares_parse_aaaa_reply(data, size, &host, NULL, NULL);
        
        // If parsing was successful, try to get address info
        if (parse_result == ARES_SUCCESS && size > sizeof(struct dns_header)) {
            // Determine how many addresses might be available based on input size
            naddrttls = (size - sizeof(struct dns_header)) / sizeof(struct ares_addr6ttl);
            if (naddrttls > 100) naddrttls = 100;  // Limit to prevent excessive allocation
            
            if (naddrttls > 0) {
                addrttls = (struct ares_addr6ttl*)malloc(naddrttls * sizeof(struct ares_addr6ttl));
                if (addrttls != NULL) {
                    int temp_naddrttls = naddrttls;
                    // Parse again to fill the addrttls array
                    ares_parse_aaaa_reply(data, size, NULL, addrttls, &temp_naddrttls);
                }
            }
        } else {
            // Try with empty reply structure to test error handling
            const unsigned char empty_reply[] = {0};
            ares_parse_aaaa_reply(empty_reply, sizeof(empty_reply), &host, NULL, NULL);
        }
        
        // Free the hostent if allocated
        if (host != NULL) {
            // Free the hostent structure members properly
            if (host->h_name) {
                free(host->h_name);
            }
            if (host->h_aliases) {
                for (int i = 0; host->h_aliases[i] != NULL; i++) {
                    free(host->h_aliases[i]);
                }
                free(host->h_aliases);
            }
            if (host->h_addr_list) {
                for (int i = 0; host->h_addr_list[i] != NULL; i++) {
                    free(host->h_addr_list[i]);
                }
                free(host->h_addr_list);
            }
            free(host);
        }
        
        // Free allocated addr6ttl array
        if (addrttls) {
            free(addrttls);
        }
    } else {
        // Test with minimal data to trigger error conditions
        struct hostent *host = NULL;
        const unsigned char minimal_data[] = {0};
        ares_parse_aaaa_reply(minimal_data, sizeof(minimal_data), &host, NULL, NULL);
    }

    // Clean up the channel
    ares_destroy(channel);

    // Clean up the library
    ares_library_cleanup();

    return 0;
}
