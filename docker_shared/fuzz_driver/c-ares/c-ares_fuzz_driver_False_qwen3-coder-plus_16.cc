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
// This driver tests the following APIs:
// - ares_expand_name
// - ares_parse_srv_reply
// - ares_parse_aaaa_reply
// - ares_free_data
// - ares_parse_ptr_reply
// - ares_parse_a_reply

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 10) {
        return 0;
    }

    // Calculate split points for different sections of the input data
    size_t section_size = size / 3;
    if (section_size < 5) {
        return 0;
    }

    // Section 1: Data for ares_expand_name and related operations
    const uint8_t *expand_data = data;
    size_t expand_size = section_size;
    
    // Section 2: Data for ares_parse_srv_reply and ares_parse_aaaa_reply
    const uint8_t *parse_data = data + section_size;
    size_t parse_size = section_size;
    
    // Section 3: Data for ares_parse_ptr_reply and ares_parse_a_reply
    const uint8_t *ptr_parse_data = data + 2 * section_size;
    size_t ptr_parse_size = size - 2 * section_size;

    // Test ares_expand_name
    char *expanded_name = nullptr;
    long enc_len = 0;
    int result = ares_expand_name(expand_data, expand_data, static_cast<int>(expand_size), &expanded_name, &enc_len);
    if (result == ARES_SUCCESS && expanded_name) {
        // Free the expanded name if allocated
        ares_free_string(expanded_name);
    }

    // Test ares_parse_srv_reply
    struct ares_srv_reply *srv_out = nullptr;
    result = ares_parse_srv_reply(parse_data, static_cast<int>(parse_size), &srv_out);
    if (result == ARES_SUCCESS && srv_out) {
        // Free the parsed SRV reply data
        ares_free_data(srv_out);
    }

    // Test ares_parse_aaaa_reply
    struct hostent *host_aaaa = nullptr;
    struct ares_addr6ttl addrttls_aaaa[10];
    int naddrttls_aaaa = 10;
    result = ares_parse_aaaa_reply(parse_data, static_cast<int>(parse_size), &host_aaaa, addrttls_aaaa, &naddrttls_aaaa);
    if (host_aaaa) {
        ares_free_hostent(host_aaaa);
    }

    // Test ares_parse_ptr_reply
    struct hostent *host_ptr = nullptr;
    // For PTR parsing, we need a valid IP address structure - use dummy IPv4 address
    struct in_addr dummy_addr;
    memset(&dummy_addr, 0, sizeof(dummy_addr));
    result = ares_parse_ptr_reply(ptr_parse_data, static_cast<int>(ptr_parse_size), 
                                  &dummy_addr, sizeof(dummy_addr), AF_INET, &host_ptr);
    if (result == ARES_SUCCESS && host_ptr) {
        ares_free_hostent(host_ptr);
    }

    // Test ares_parse_a_reply
    struct hostent *host_a = nullptr;
    struct ares_addrttl addrttls_a[10];
    int naddrttls_a = 10;
    result = ares_parse_a_reply(ptr_parse_data, static_cast<int>(ptr_parse_size), &host_a, addrttls_a, &naddrttls_a);
    if (result == ARES_SUCCESS && host_a) {
        ares_free_hostent(host_a);
    }

    // Additional test for ares_expand_name with different parameters
    char *expanded_name2 = nullptr;
    long enc_len2 = 0;
    // Use a subset of data to ensure valid encoding
    if (expand_size > 5) {
        result = ares_expand_name(expand_data + 1, expand_data, static_cast<int>(expand_size - 1), &expanded_name2, &enc_len2);
        if (result == ARES_SUCCESS && expanded_name2) {
            ares_free_string(expanded_name2);
        }
    }

    // Additional test for ares_parse_srv_reply with modified data
    struct ares_srv_reply *srv_out2 = nullptr;
    if (parse_size > 5) {
        result = ares_parse_srv_reply(parse_data + 1, static_cast<int>(parse_size - 1), &srv_out2);
        if (result == ARES_SUCCESS && srv_out2) {
            ares_free_data(srv_out2);
        }
    }

    // Additional test for ares_parse_aaaa_reply with modified data
    struct hostent *host_aaaa2 = nullptr;
    if (parse_size > 5) {
        result = ares_parse_aaaa_reply(parse_data + 1, static_cast<int>(parse_size - 1), &host_aaaa2, addrttls_aaaa, &naddrttls_aaaa);
        if (host_aaaa2) {
            ares_free_hostent(host_aaaa2);
        }
    }

    // Additional test for ares_parse_ptr_reply with modified data
    struct hostent *host_ptr2 = nullptr;
    if (ptr_parse_size > 5) {
        result = ares_parse_ptr_reply(ptr_parse_data + 1, static_cast<int>(ptr_parse_size - 1), 
                                      &dummy_addr, sizeof(dummy_addr), AF_INET, &host_ptr2);
        if (result == ARES_SUCCESS && host_ptr2) {
            ares_free_hostent(host_ptr2);
        }
    }

    // Additional test for ares_parse_a_reply with modified data
    struct hostent *host_a2 = nullptr;
    if (ptr_parse_size > 5) {
        result = ares_parse_a_reply(ptr_parse_data + 1, static_cast<int>(ptr_parse_size - 1), &host_a2, addrttls_a, &naddrttls_a);
        if (result == ARES_SUCCESS && host_a2) {
            ares_free_hostent(host_a2);
        }
    }

    return 0;
}
