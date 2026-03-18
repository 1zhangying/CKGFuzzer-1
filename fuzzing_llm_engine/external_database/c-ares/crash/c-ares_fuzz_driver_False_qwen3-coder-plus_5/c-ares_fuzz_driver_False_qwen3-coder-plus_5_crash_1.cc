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
    // Validate minimum input size requirements
    if (size < 10) {
        return 0;
    }

    // Create a local copy of the input data to avoid modifying original
    unsigned char *local_data = (unsigned char*)malloc(size);
    if (!local_data) {
        return 0;
    }
    memcpy(local_data, data, size);

    // Variables for different API calls
    char *expanded_name = NULL;
    long enc_len = 0;
    struct ares_srv_reply *srv_out = NULL;
    struct hostent *host = NULL;
    struct ares_addr6ttl addrttls[10];
    int naddrttls = 10;
    unsigned char *query_buf = NULL;
    int query_buflen = 0;
    unsigned char *expanded_string = NULL;
    long str_enclen = 0;

    // Call ares_expand_name
    if (size >= 2) {
        int name_result = ares_expand_name(local_data, local_data, size, &expanded_name, &enc_len);
        if (name_result == ARES_SUCCESS && expanded_name) {
            // Test ares_free_string with the result of expand_name
            ares_free_string(expanded_name);
            expanded_name = NULL;
        }
    }

    // Call ares_parse_srv_reply
    int srv_result = ares_parse_srv_reply(local_data, size, &srv_out);
    if (srv_result == ARES_SUCCESS && srv_out) {
        // Free the parsed SRV reply structure
        ares_free_data(srv_out);
        srv_out = NULL;
    }

    // Call ares_parse_aaaa_reply
    int aaaa_result = ares_parse_aaaa_reply(local_data, size, &host, addrttls, &naddrttls);
    if (aaaa_result == ARES_SUCCESS && host) {
        // Free the hostent structure if allocated
        if (host->h_name) {
            ares_free_string(host->h_name);
        }
        if (host->h_aliases) {
            for (int i = 0; host->h_aliases[i]; i++) {
                ares_free_string(host->h_aliases[i]);
            }
            free(host->h_aliases);
        }
        if (host->h_addr_list) {
            for (int i = 0; host->h_addr_list[i]; i++) {
                free(host->h_addr_list[i]);
            }
            free(host->h_addr_list);
        }
        free(host);
        host = NULL;
    }

    // Call ares_create_query with different parameters
    const char *test_name = "example.com";
    int create_result = ares_create_query(
        test_name,
        C_IN,           // DNS class
        T_A,            // Record type
        1234,           // ID
        1,              // Recursion desired
        &query_buf,     // Buffer pointer
        &query_buflen,  // Buffer length
        0               // Max UDP size
    );
    if (create_result == ARES_SUCCESS && query_buf) {
        free(query_buf);
        query_buf = NULL;
        query_buflen = 0;
    }

    // Try ares_create_query with EDNS enabled
    int create_result_edns = ares_create_query(
        test_name,
        C_IN,
        T_AAAA,
        5678,
        1,
        &query_buf,
        &query_buflen,
        4096
    );
    if (create_result_edns == ARES_SUCCESS && query_buf) {
        free(query_buf);
        query_buf = NULL;
        query_buflen = 0;
    }

    // Call ares_expand_string
    if (size >= 2) {
        int str_result = ares_expand_string(local_data, local_data, size, &expanded_string, &str_enclen);
        if (str_result == ARES_SUCCESS && expanded_string) {
            // Free the expanded string
            ares_free_string(expanded_string);
            expanded_string = NULL;
        }
    }

    // Additional tests with different parameters
    // Try ares_expand_name with different offset
    if (size >= 10) {
        int offset = data[0] % (size - 2);
        if (offset >= 0 && offset < size - 2) {
            char *temp_name = NULL;
            long temp_len = 0;
            int offset_result = ares_expand_name(local_data + offset, local_data, size, &temp_name, &temp_len);
            if (offset_result == ARES_SUCCESS && temp_name) {
                ares_free_string(temp_name);
                temp_name = NULL;
            }
        }
    }

    // Clean up any remaining resources
    if (expanded_name) {
        ares_free_string(expanded_name);
    }
    
    if (srv_out) {
        ares_free_data(srv_out);
    }
    
    if (host) {
        if (host->h_name) {
            ares_free_string(host->h_name);
        }
        if (host->h_aliases) {
            for (int i = 0; host->h_aliases[i]; i++) {
                ares_free_string(host->h_aliases[i]);
            }
            free(host->h_aliases);
        }
        if (host->h_addr_list) {
            for (int i = 0; host->h_addr_list[i]; i++) {
                free(host->h_addr_list[i]);
            }
            free(host->h_addr_list);
        }
        free(host);
    }
    
    if (query_buf) {
        free(query_buf);
    }
    
    if (expanded_string) {
        ares_free_string(expanded_string);
    }

    free(local_data);
    
    return 0;
}
