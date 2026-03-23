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
// - ares_free_string
// - ares_expand_string
// - ares_parse_a_reply

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size < 4) {
        return 0;
    }

    // Split input data into segments for different tests
    size_t offset = 0;
    
    // Test 1: ares_expand_name and ares_free_string
    if (offset + 1 < size) {
        size_t expand_size = data[offset] % (size - offset);
        if (expand_size > 0 && offset + expand_size <= size) {
            char *expanded_name = NULL;
            long enclen = 0;
            
            int result = ares_expand_name(data + offset, data, size, 
                                         &expanded_name, &enclen);
            
            if (result == ARES_SUCCESS && expanded_name != NULL) {
                ares_free_string(expanded_name);
            }
            
            offset += expand_size;
        }
    }
    
    // Test 2: ares_expand_string
    if (offset + 1 < size) {
        size_t expand_str_size = data[offset] % (size - offset);
        if (expand_str_size > 0 && offset + expand_str_size <= size) {
            unsigned char *expanded_str = NULL;
            long str_enclen = 0;
            
            int result = ares_expand_string(data + offset, data, size,
                                          &expanded_str, &str_enclen);
            
            if (result == ARES_SUCCESS && expanded_str != NULL) {
                ares_free_string(expanded_str);
            }
            
            offset += expand_str_size;
        }
    }
    
    // Test 3: ares_parse_a_reply
    if (offset + 1 < size) {
        size_t a_reply_size = data[offset] % (size - offset);
        if (a_reply_size > HFIXEDSZ && offset + a_reply_size <= size) {
            struct hostent *host = NULL;
            struct ares_addrttl addrttls[10];
            int naddrttls = 10;
            
            int result = ares_parse_a_reply(data + offset, a_reply_size,
                                           &host, addrttls, &naddrttls);
            
            if (host != NULL) {
                // Free host structure if allocated
                if (host->h_addr_list) {
                    free(host->h_addr_list[0]);
                    free(host->h_addr_list);
                }
                if (host->h_aliases) {
                    for (int i = 0; host->h_aliases[i]; i++) {
                        free(host->h_aliases[i]);
                    }
                    free(host->h_aliases);
                }
                if (host->h_name) {
                    free(host->h_name);
                }
                free(host);
            }
            
            offset += a_reply_size;
        }
    }
    
    // Test 4: ares_parse_aaaa_reply
    if (offset + 1 < size) {
        size_t aaaa_reply_size = data[offset] % (size - offset);
        if (aaaa_reply_size > HFIXEDSZ && offset + aaaa_reply_size <= size) {
            struct hostent *host = NULL;
            struct ares_addr6ttl addrttls[10];
            int naddrttls = 10;
            
            int result = ares_parse_aaaa_reply(data + offset, aaaa_reply_size,
                                              &host, addrttls, &naddrttls);
            
            if (host != NULL) {
                // Free host structure if allocated
                if (host->h_addr_list) {
                    free(host->h_addr_list[0]);
                    free(host->h_addr_list);
                }
                if (host->h_aliases) {
                    for (int i = 0; host->h_aliases[i]; i++) {
                        free(host->h_aliases[i]);
                    }
                    free(host->h_aliases);
                }
                if (host->h_name) {
                    free(host->h_name);
                }
                free(host);
            }
            
            offset += aaaa_reply_size;
        }
    }
    
    // Test 5: ares_parse_srv_reply
    if (offset + 1 < size) {
        size_t srv_reply_size = data[offset] % (size - offset);
        if (srv_reply_size > HFIXEDSZ && offset + srv_reply_size <= size) {
            struct ares_srv_reply *srv_out = NULL;
            
            int result = ares_parse_srv_reply(data + offset, srv_reply_size,
                                             &srv_out);
            
            // Free the srv reply structure if allocated
            if (srv_out != NULL) {
                struct ares_srv_reply *current = srv_out;
                while (current) {
                    struct ares_srv_reply *next = current->next;
                    if (current->host) {
                        ares_free_string(current->host);
                    }
                    ares_free_data(current);
                    current = next;
                }
            }
            
            offset += srv_reply_size;
        }
    }
    
    return 0;
}
