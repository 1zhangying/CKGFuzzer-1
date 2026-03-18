#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation that tests multiple c-ares parsing functions
// Each function is tested with the same input data to maximize code coverage
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early return if input is too small to contain a valid DNS packet header
    if (size < HFIXEDSZ) {
        return 0;
    }

    // Convert size to int as the c-ares functions expect int parameters
    int alen = static_cast<int>(size);
    
    // Limit size to prevent integer overflow issues
    if (size > INT_MAX) {
        return 0;
    }

    // Test ares_parse_srv_reply
    {
        struct ares_srv_reply *srv_out = NULL;
        int result = ares_parse_srv_reply(data, alen, &srv_out);
        
        // Clean up allocated resources
        if (srv_out) {
            ares_free_data(srv_out);
        }
    }

    // Test ares_parse_aaaa_reply
    {
        struct hostent *host_aaaa = NULL;
        struct ares_addr6ttl addrttls_aaaa[10];  // Pre-allocate array
        int naddrttls_aaaa = 10;
        
        int result = ares_parse_aaaa_reply(data, alen, &host_aaaa, addrttls_aaaa, &naddrttls_aaaa);
        
        // Clean up allocated resources
        if (host_aaaa) {
            ares_free_hostent(host_aaaa);
        }
    }

    // Test ares_parse_txt_reply
    {
        struct ares_txt_reply *txt_out = NULL;
        int result = ares_parse_txt_reply(data, alen, &txt_out);
        
        // Clean up allocated resources
        if (txt_out) {
            ares_free_data(txt_out);
        }
    }

    // Test ares_parse_mx_reply
    {
        struct ares_mx_reply *mx_out = NULL;
        int result = ares_parse_mx_reply(data, alen, &mx_out);
        
        // Clean up allocated resources
        if (mx_out) {
            ares_free_data(mx_out);
        }
    }

    // Test ares_parse_ptr_reply
    {
        struct hostent *host_ptr = NULL;
        
        // Prepare dummy address for testing - IPv4 address
        unsigned int dummy_addr = 0x7f000001; // 127.0.0.1
        
        int result = ares_parse_ptr_reply(data, alen, &dummy_addr, sizeof(dummy_addr), AF_INET, &host_ptr);
        
        // Clean up allocated resources
        if (host_ptr) {
            ares_free_hostent(host_ptr);
        }
    }

    // Test ares_parse_a_reply
    {
        struct hostent *host_a = NULL;
        struct ares_addrttl addrttls_a[10];  // Pre-allocate array
        int naddrttls_a = 10;
        
        int result = ares_parse_a_reply(data, alen, &host_a, addrttls_a, &naddrttls_a);
        
        // Clean up allocated resources
        if (host_a) {
            ares_free_hostent(host_a);
        }
    }

    return 0;
}
