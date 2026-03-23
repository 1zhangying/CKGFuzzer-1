#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for testing c-ares parsing functions
// This driver tests ares_parse_srv_reply, ares_parse_a_reply, and their associated cleanup functions
// It uses the fuzz input data to simulate DNS response buffers and verifies proper parsing and memory management

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be valid DNS packet
    if (size < HFIXEDSZ) {  // HFIXEDSZ is the minimum DNS header size
        return 0;
    }

    // Limit the maximum size to prevent excessive memory allocation
    size_t max_size = 65536;  // 64KB should be sufficient for DNS packets
    if (size > max_size) {
        size = max_size;
    }

    // Cast the input data to unsigned char* as expected by the APIs
    const unsigned char* buf = reinterpret_cast<const unsigned char*>(data);

    // Test ares_parse_a_reply
    struct hostent* host = nullptr;
    struct ares_addrttl addrttls[10];  // Buffer for up to 10 address-TTL pairs
    int naddrttls = 10;  // Number of address-TTL slots available
    
    int a_status = ares_parse_a_reply(buf, static_cast<int>(size), &host, addrttls, &naddrttls);
    
    // Properly free the hostent structure if allocated
    if (host) {
        ares_free_hostent(host);
        host = nullptr;
    }
    
    // Test ares_parse_srv_reply
    struct ares_srv_reply* srv_out = nullptr;
    
    int srv_status = ares_parse_srv_reply(buf, static_cast<int>(size), &srv_out);
    
    // Properly free the SRV reply structure if allocated
    if (srv_out) {
        ares_free_data(srv_out);
        srv_out = nullptr;
    }
    
    // Additional test: try with different buffer sizes to trigger edge cases
    if (size > HFIXEDSZ + 10) {
        // Try with a smaller size to test partial parsing scenarios
        size_t mid_size = HFIXEDSZ + 5;
        struct ares_srv_reply* srv_mid = nullptr;
        
        int mid_status = ares_parse_srv_reply(buf, static_cast<int>(mid_size), &srv_mid);
        
        if (srv_mid) {
            ares_free_data(srv_mid);
            srv_mid = nullptr;
        }
    }
    
    // Test error conditions by providing invalid data sizes
    if (size >= HFIXEDSZ) {
        struct ares_srv_reply* srv_small = nullptr;
        
        // Try with minimal size that might pass initial checks but fail later
        int small_status = ares_parse_srv_reply(buf, HFIXEDSZ, &srv_small);
        
        if (srv_small) {
            ares_free_data(srv_small);
            srv_small = nullptr;
        }
    }
    
    // Test ares_parse_a_reply with zero addresses requested
    int naddrttls_zero = 0;
    struct hostent* host_zero = nullptr;
    int a_status_zero = ares_parse_a_reply(buf, static_cast<int>(size), &host_zero, nullptr, &naddrttls_zero);
    
    if (host_zero) {
        ares_free_hostent(host_zero);
        host_zero = nullptr;
    }
    
    // All allocated memory should be freed at this point
    return 0;
}
