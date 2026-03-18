#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>
#include <arpa/inet.h>  // Added for inet_addr function

// Fuzz driver implementation to test c-ares parsing functions
// This driver tests the following APIs:
// - ares_parse_srv_reply
// - ares_parse_txt_reply
// - ares_parse_aaaa_reply
// - ares_parse_mx_reply
// - ares_parse_ptr_reply
// - ares_parse_a_reply

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if there's not enough data for basic DNS header
    if (size < HFIXEDSZ) {
        return 0;
    }

    // Cast the input data to unsigned char* for the library functions
    const unsigned char* buf = reinterpret_cast<const unsigned char*>(data);

    // Test ares_parse_srv_reply
    struct ares_srv_reply *srv_out = NULL;
    int srv_result = ares_parse_srv_reply(buf, static_cast<int>(size), &srv_out);
    if (srv_result == ARES_SUCCESS && srv_out != NULL) {
        // Clean up the result if successful
        struct ares_srv_reply *current_srv = srv_out;
        while (current_srv != NULL) {
            struct ares_srv_reply *next = current_srv->next;
            ares_free_data(current_srv);
            current_srv = next;
        }
    }

    // Test ares_parse_txt_reply
    struct ares_txt_reply *txt_out = NULL;
    int txt_result = ares_parse_txt_reply(buf, static_cast<int>(size), &txt_out);
    if (txt_result == ARES_SUCCESS && txt_out != NULL) {
        // Clean up the result if successful
        struct ares_txt_reply *current_txt = txt_out;
        while (current_txt != NULL) {
            struct ares_txt_reply *next = current_txt->next;
            ares_free_data(current_txt);
            current_txt = next;
        }
    }

    // Test ares_parse_aaaa_reply
    struct hostent *host_aaaa = NULL;
    struct ares_addr6ttl addrttls_aaaa[10];  // Limit to 10 entries to prevent excessive allocations
    int naddrttls_aaaa = 10;
    int aaaa_result = ares_parse_aaaa_reply(buf, static_cast<int>(size), &host_aaaa, addrttls_aaaa, &naddrttls_aaaa);
    if (host_aaaa != NULL) {
        ares_free_hostent(host_aaaa);
    }

    // Test ares_parse_mx_reply
    struct ares_mx_reply *mx_out = NULL;
    int mx_result = ares_parse_mx_reply(buf, static_cast<int>(size), &mx_out);
    if (mx_result == ARES_SUCCESS && mx_out != NULL) {
        // Clean up the result if successful
        struct ares_mx_reply *current_mx = mx_out;
        while (current_mx != NULL) {
            struct ares_mx_reply *next = current_mx->next;
            ares_free_data(current_mx);
            current_mx = next;
        }
    }

    // Test ares_parse_ptr_reply
    struct hostent *host_ptr = NULL;
    // Create dummy address for PTR parsing
    struct in_addr dummy_addr;
    dummy_addr.s_addr = inet_addr("127.0.0.1");  // Now inet_addr is available after including arpa/inet.h
    int ptr_result = ares_parse_ptr_reply(buf, static_cast<int>(size), 
                                          &dummy_addr, sizeof(dummy_addr), 
                                          AF_INET, &host_ptr);
    if (host_ptr != NULL) {
        ares_free_hostent(host_ptr);
    }

    // Test ares_parse_a_reply
    struct hostent *host_a = NULL;
    struct ares_addrttl addrttls_a[10];  // Limit to 10 entries to prevent excessive allocations
    int naddrttls_a = 10;
    int a_result = ares_parse_a_reply(buf, static_cast<int>(size), &host_a, addrttls_a, &naddrttls_a);
    if (host_a != NULL) {
        ares_free_hostent(host_a);
    }

    return 0;
}
