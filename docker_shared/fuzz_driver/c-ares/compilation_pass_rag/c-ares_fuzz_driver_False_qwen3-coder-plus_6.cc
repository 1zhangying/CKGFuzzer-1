#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation to test c-ares library APIs
// This driver tests: ares_parse_srv_reply, ares_process_fd, ares_parse_aaaa_reply,
// ares_free_data, ares_free_string, ares_free_hostent

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < sizeof(int)) {
        return 0;
    }

    // Split the input data into different segments for various API calls
    size_t srv_size = size / 3;
    if (srv_size < HFIXEDSZ) {
        srv_size = HFIXEDSZ;  // Minimum size needed for DNS header
    }
    
    size_t aaaa_size = (size - srv_size) / 2;
    if (aaaa_size < HFIXEDSZ) {
        aaaa_size = HFIXEDSZ;
    }
    
    size_t remaining_size = size - srv_size - aaaa_size;
    
    // Ensure we don't exceed original size
    if (srv_size + aaaa_size > size) {
        srv_size = size / 2;
        aaaa_size = size - srv_size;
    }

    // Test ares_parse_srv_reply
    struct ares_srv_reply *srv_out = NULL;
    if (srv_size <= size && srv_size >= HFIXEDSZ) {
        int srv_result = ares_parse_srv_reply(data, (int)srv_size, &srv_out);
        // Handle the result but don't return early since we want to test other APIs
    }

    // Free the SRV data if allocated
    if (srv_out) {
        ares_free_data(srv_out);
        srv_out = NULL;
    }

    // Test ares_parse_aaaa_reply
    struct hostent *host = NULL;
    struct ares_addr6ttl *addrttls = NULL;
    int naddrttls = 0;
    
    if (aaaa_size <= size - srv_size && aaaa_size >= HFIXEDSZ) {
        // Allocate space for address TTLs if possible
        if (remaining_size >= sizeof(struct ares_addr6ttl)) {
            addrttls = (struct ares_addr6ttl*)malloc(sizeof(struct ares_addr6ttl));
            if (addrttls) {
                naddrttls = 1;
            }
        }
        
        const unsigned char *aaaa_data = data + srv_size;
        int aaaa_result = ares_parse_aaaa_reply(aaaa_data, (int)aaaa_size, &host, addrttls, &naddrttls);
        // Process result but continue execution
    }

    // Free the hostent structure if allocated
    if (host) {
        ares_free_hostent(host);
        host = NULL;
    }
    
    // Free the address TTL array if allocated
    if (addrttls) {
        free(addrttls);
        addrttls = NULL;
    }

    // Test ares_process_fd - need to initialize a channel first
    ares_channel channel = NULL;
    int init_result = ares_init(&channel);
    if (init_result == ARES_SUCCESS && channel != NULL) {
        // Use ARES_SOCKET_BAD for both read and write fd to avoid actual I/O
        ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        
        // Clean up the channel
        ares_destroy(channel);
    }

    // Test ares_free_string with a dummy string
    char *dummy_str = (char*)malloc(10);
    if (dummy_str) {
        strcpy(dummy_str, "test");
        ares_free_string(dummy_str);
    }

    // Additional edge case testing with malformed data
    // Test with minimal valid DNS header
    if (size >= HFIXEDSZ) {
        // Create a minimal DNS header with query count=1 and answer count=0
        unsigned char minimal_header[HFIXEDSZ] = {0};
        DNS_HEADER_SET_QID(minimal_header, 0x1234);
        DNS_HEADER_SET_QR(minimal_header, 0);  // Query
        DNS_HEADER_SET_OPCODE(minimal_header, 0);
        DNS_HEADER_SET_AA(minimal_header, 0);
        DNS_HEADER_SET_TC(minimal_header, 0);
        DNS_HEADER_SET_RD(minimal_header, 0);
        DNS_HEADER_SET_RA(minimal_header, 0);
        DNS_HEADER_SET_Z(minimal_header, 0);
        DNS_HEADER_SET_RCODE(minimal_header, 0);
        DNS_HEADER_SET_QDCOUNT(minimal_header, 1);
        DNS_HEADER_SET_ANCOUNT(minimal_header, 0);
        DNS_HEADER_SET_NSCOUNT(minimal_header, 0);
        DNS_HEADER_SET_ARCOUNT(minimal_header, 0);

        struct ares_srv_reply *temp_srv = NULL;
        ares_parse_srv_reply(minimal_header, HFIXEDSZ, &temp_srv);
        if (temp_srv) {
            ares_free_data(temp_srv);
        }
    }

    return 0;
}
