#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation to test c-ares parsing functions
// This driver tests the following APIs:
// - ares_parse_srv_reply
// - ares_parse_txt_reply
// - ares_parse_aaaa_reply
// - ares_parse_mx_reply
// - ares_parse_ptr_reply
// - ares_parse_a_reply

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if data is too small to be meaningful
    if (size < sizeof(dns_hdr)) {
        return 0;
    }

    // Test ares_parse_srv_reply
    {
        struct ares_srv_reply *srv_out = NULL;
        int result = ares_parse_srv_reply(data, static_cast<int>(size), &srv_out);
        
        // Clean up allocated resources
        if (srv_out) {
            ares_free_data(srv_out);
        }
    }

    // Test ares_parse_txt_reply
    {
        struct ares_txt_reply *txt_out = NULL;
        int result = ares_parse_txt_reply(data, static_cast<int>(size), &txt_out);
        
        // Clean up allocated resources
        if (txt_out) {
            ares_free_data(txt_out);
        }
    }

    // Test ares_parse_aaaa_reply
    {
        struct hostent *host_aaaa = NULL;
        struct ares_addr6ttl addrttls_aaaa[10];  // Fixed-size array to limit allocations
        int naddrttls_aaaa = 10;
        int result = ares_parse_aaaa_reply(data, static_cast<int>(size), &host_aaaa, 
                                          addrttls_aaaa, &naddrttls_aaaa);
        
        // Clean up allocated resources
        if (host_aaaa) {
            ares_free_hostent(host_aaaa);
        }
    }

    // Test ares_parse_mx_reply
    {
        struct ares_mx_reply *mx_out = NULL;
        int result = ares_parse_mx_reply(data, static_cast<int>(size), &mx_out);
        
        // Clean up allocated resources
        if (mx_out) {
            ares_free_data(mx_out);
        }
    }

    // Test ares_parse_ptr_reply
    {
        struct hostent *host_ptr = NULL;
        // Using dummy address data for testing
        unsigned char dummy_addr[16] = {0};
        int addrlen = 4; // For IPv4
        int family = AF_INET;
        int result = ares_parse_ptr_reply(data, static_cast<int>(size), 
                                         dummy_addr, addrlen, family, &host_ptr);
        
        // Clean up allocated resources
        if (host_ptr) {
            ares_free_hostent(host_ptr);
        }
    }

    // Test ares_parse_a_reply
    {
        struct hostent *host_a = NULL;
        struct ares_addrttl addrttls_a[10];  // Fixed-size array to limit allocations
        int naddrttls_a = 10;
        int result = ares_parse_a_reply(data, static_cast<int>(size), &host_a, 
                                       addrttls_a, &naddrttls_a);
        
        // Clean up allocated resources
        if (host_a) {
            ares_free_hostent(host_a);
        }
    }

    return 0;
}
