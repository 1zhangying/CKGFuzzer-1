#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for testing DNS parsing functions
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Parse SRV reply
    struct ares_srv_reply *srv_out = NULL;
    if (size >= sizeof(unsigned char)) {
        int srv_result = ares_parse_srv_reply(data, static_cast<int>(size), &srv_out);
        // Free allocated SRV reply data
        if (srv_out) {
            ares_free_data(srv_out);
        }
    }

    // Parse TXT reply
    struct ares_txt_reply *txt_out = NULL;
    if (size >= sizeof(unsigned char)) {
        int txt_result = ares_parse_txt_reply(data, static_cast<int>(size), &txt_out);
        // Free allocated TXT reply data
        if (txt_out) {
            ares_free_data(txt_out);
        }
    }

    // Parse AAAA reply
    struct hostent *aaaa_host = NULL;
    struct ares_addr6ttl aaaa_addrttls[10];  // Fixed-size array for testing
    int aaaa_naddrttls = 10;
    if (size >= sizeof(unsigned char)) {
        int aaaa_result = ares_parse_aaaa_reply(data, static_cast<int>(size), &aaaa_host, aaaa_addrttls, &aaaa_naddrttls);
        // Free allocated hostent structure
        if (aaaa_host) {
            ares_free_hostent(aaaa_host);
        }
    }

    // Parse MX reply
    struct ares_mx_reply *mx_out = NULL;
    if (size >= sizeof(unsigned char)) {
        int mx_result = ares_parse_mx_reply(data, static_cast<int>(size), &mx_out);
        // Free allocated MX reply data
        if (mx_out) {
            ares_free_data(mx_out);
        }
    }

    // Parse PTR reply
    struct hostent *ptr_host = NULL;
    // Using dummy address for testing
    struct in_addr dummy_addr;
    memset(&dummy_addr, 0, sizeof(dummy_addr));
    if (size >= sizeof(unsigned char)) {
        int ptr_result = ares_parse_ptr_reply(data, static_cast<int>(size), 
                                              &dummy_addr, sizeof(dummy_addr), AF_INET, &ptr_host);
        // Free allocated hostent structure
        if (ptr_host) {
            ares_free_hostent(ptr_host);
        }
    }

    // Parse A reply
    struct hostent *a_host = NULL;
    struct ares_addrttl a_addrttls[10];  // Fixed-size array for testing
    int a_naddrttls = 10;
    if (size >= sizeof(unsigned char)) {
        int a_result = ares_parse_a_reply(data, static_cast<int>(size), &a_host, a_addrttls, &a_naddrttls);
        // Free allocated hostent structure
        if (a_host) {
            ares_free_hostent(a_host);
        }
    }

    return 0;
}
