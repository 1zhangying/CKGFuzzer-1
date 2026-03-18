#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be meaningful
    if (size < 10) {
        return 0;
    }

    // Split input data into different segments for various API calls
    size_t offset = 0;
    
    // For ares_create_query, extract a name string first
    if (offset >= size) return 0;
    size_t name_len = data[offset] % 256;  // Limit name length to prevent issues
    offset++;
    
    if (offset + name_len > size) name_len = size - offset;
    if (name_len == 0) name_len = 1;
    
    char *name = (char *)malloc(name_len + 1);
    if (!name) return 0;
    
    memcpy(name, data + offset, name_len);
    name[name_len] = '\0';
    
    // Ensure name is a valid domain name (replace null chars with dots)
    for (size_t i = 0; i < name_len; i++) {
        if (name[i] == '\0') name[i] = '.';
    }
    
    offset += name_len;
    
    // Extract parameters for ares_create_query
    if (offset + 12 > size) {
        free(name);
        return 0;
    }
    
    int dnsclass = data[offset];
    offset++;
    int type = data[offset];
    offset++;
    unsigned short id = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    int rd = data[offset];
    offset++;
    int max_udp_size = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    // Extract remaining data for parsing functions
    size_t remaining_size = size - offset;
    const uint8_t *remaining_data = data + offset;
    
    // Call ares_create_query
    unsigned char *query_buf = NULL;
    int query_buflen = 0;
    int result = ares_create_query(
        name,
        dnsclass,
        type,
        id,
        rd,
        &query_buf,
        &query_buflen,
        max_udp_size
    );
    
    // Regardless of result, proceed with parsing functions using original input data
    
    // Call ares_parse_a_reply
    struct hostent *host_a = NULL;
    struct ares_addrttl addrttls_a[10];
    int naddrttls_a = 10;
    ares_parse_a_reply(remaining_data, (int)remaining_size, &host_a, addrttls_a, &naddrttls_a);
    
    // Free hostent if allocated
    if (host_a) {
        ares_free_hostent(host_a);
    }
    
    // Call ares_parse_aaaa_reply
    struct hostent *host_aaaa = NULL;
    struct ares_addr6ttl addrttls_aaaa[10];
    int naddrttls_aaaa = 10;
    ares_parse_aaaa_reply(remaining_data, (int)remaining_size, &host_aaaa, addrttls_aaaa, &naddrttls_aaaa);
    
    // Free hostent if allocated
    if (host_aaaa) {
        ares_free_hostent(host_aaaa);
    }
    
    // Call ares_parse_txt_reply
    struct ares_txt_reply *txt_out = NULL;
    ares_parse_txt_reply(remaining_data, (int)remaining_size, &txt_out);
    
    // Free txt reply if allocated
    if (txt_out) {
        ares_free_data(txt_out);
    }
    
    // Call ares_parse_mx_reply
    struct ares_mx_reply *mx_out = NULL;
    ares_parse_mx_reply(remaining_data, (int)remaining_size, &mx_out);
    
    // Free mx reply if allocated
    if (mx_out) {
        ares_free_data(mx_out);
    }
    
    // Call ares_parse_srv_reply
    struct ares_srv_reply *srv_out = NULL;
    ares_parse_srv_reply(remaining_data, (int)remaining_size, &srv_out);
    
    // Free srv reply if allocated
    if (srv_out) {
        ares_free_data(srv_out);
    }
    
    // Free query buffer if allocated
    if (query_buf) {
        ares_free_string(query_buf);
    }
    
    // Free allocated name
    free(name);
    
    return 0;
}
