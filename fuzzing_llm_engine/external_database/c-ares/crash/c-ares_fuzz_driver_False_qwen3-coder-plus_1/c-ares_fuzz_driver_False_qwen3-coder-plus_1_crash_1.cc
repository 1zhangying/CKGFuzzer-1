#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for c-ares library APIs
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if size is too small to do anything meaningful
    if (size < 10) {
        return 0;
    }

    // Split the input data into different segments for different API calls
    size_t pos = 0;
    
    // Extract a domain name (null-terminated string) from input data
    size_t domain_len = data[pos] % 50; // Limit domain name length
    pos++;
    if (pos + domain_len >= size) {
        domain_len = size - pos;
    }
    if (domain_len == 0) {
        return 0;
    }
    
    char *domain_name = (char*)malloc(domain_len + 1);
    if (!domain_name) {
        return 0;
    }
    
    memcpy(domain_name, data + pos, domain_len);
    domain_name[domain_len] = '\0';
    pos += domain_len;
    
    // Sanitize domain name to avoid bad characters
    for (size_t i = 0; i < domain_len; i++) {
        if (domain_name[i] == 0 || domain_name[i] == '.' || domain_name[i] == '\\') {
            domain_name[i] = 'x';
        }
    }
    
    // Create a DNS query using ares_create_query
    unsigned char *query_buf = NULL;
    int query_len = 0;
    int dns_class = C_IN;
    int dns_type = T_A; // Default to A record type
    unsigned short query_id = 1234; // Fixed query ID
    int recursion_desired = 1;
    
    // Determine DNS type from input if possible
    if (pos + 1 < size) {
        dns_type = data[pos] % 256;
        pos++;
    }
    
    int create_result = ares_create_query(
        domain_name,
        dns_class,
        dns_type,
        query_id,
        recursion_desired,
        &query_buf,
        &query_len,
        0  // max_udp_size
    );
    
    // Also try ares_mkquery which is a wrapper around ares_create_query
    unsigned char *mkquery_buf = NULL;
    int mkquery_len = 0;
    int mkquery_result = ares_mkquery(
        domain_name,
        dns_class,
        dns_type,
        query_id,
        recursion_desired,
        &mkquery_buf,
        &mkquery_len
    );
    
    // Parse A record reply if there's enough data left
    if (pos + HFIXEDSZ < size) {  // Need at least header size
        int a_reply_len = HFIXEDSZ + 4 + QFIXEDSZ; // Minimal response size for A record
        if (pos + a_reply_len > size) {
            a_reply_len = size - pos;
        }
        
        struct hostent *a_host = NULL;
        struct ares_addrttl a_addrttls[5]; // Array for up to 5 TTL entries
        int a_naddrttls = 5;
        
        int parse_a_result = ares_parse_a_reply(
            data + pos,
            a_reply_len,
            &a_host,
            a_addrttls,
            &a_naddrttls
        );
        
        // Clean up parsed hostent if created
        if (a_host) {
            // Free the hostent structure properly
            if (a_host->h_name) ares_free_string(a_host->h_name);
            if (a_host->h_aliases) {
                for (int i = 0; a_host->h_aliases[i]; i++) {
                    ares_free_string(a_host->h_aliases[i]);
                }
                ares_free_string(a_host->h_aliases);
            }
            if (a_host->h_addr_list) {
                for (int i = 0; a_host->h_addr_list[i]; i++) {
                    ares_free_string(a_host->h_addr_list[i]);
                }
                ares_free_string(a_host->h_addr_list);
            }
        }
    }
    
    // Parse AAAA record reply if there's enough data
    if (pos + HFIXEDSZ < size) {
        int aaaa_reply_len = HFIXEDSZ + 16 + QFIXEDSZ; // Minimal response size for AAAA record
        if (pos + aaaa_reply_len > size) {
            aaaa_reply_len = size - pos;
        }
        
        struct hostent *aaaa_host = NULL;
        struct ares_addr6ttl aaaa_addrttls[5];
        int aaaa_naddrttls = 5;
        
        int parse_aaaa_result = ares_parse_aaaa_reply(
            data + pos,
            aaaa_reply_len,
            &aaaa_host,
            aaaa_addrttls,
            &aaaa_naddrttls
        );
        
        // Clean up parsed hostent if created
        if (aaaa_host) {
            if (aaaa_host->h_name) ares_free_string(aaaa_host->h_name);
            if (aaaa_host->h_aliases) {
                for (int i = 0; aaaa_host->h_aliases[i]; i++) {
                    ares_free_string(aaaa_host->h_aliases[i]);
                }
                ares_free_string(aaaa_host->h_aliases);
            }
            if (aaaa_host->h_addr_list) {
                for (int i = 0; aaaa_host->h_addr_list[i]; i++) {
                    ares_free_string(aaaa_host->h_addr_list[i]);
                }
                ares_free_string(aaaa_host->h_addr_list);
            }
        }
    }
    
    // Parse SRV record reply if there's enough data
    if (pos + HFIXEDSZ < size) {
        int srv_reply_len = HFIXEDSZ + QFIXEDSZ + RRFIXEDSZ + 6; // Minimal SRV response
        if (pos + srv_reply_len > size) {
            srv_reply_len = size - pos;
        }
        
        struct ares_srv_reply *srv_out = NULL;
        
        int parse_srv_result = ares_parse_srv_reply(
            data + pos,
            srv_reply_len,
            &srv_out
        );
        
        // Clean up SRV reply if created
        if (srv_out) {
            struct ares_srv_reply *current = srv_out;
            while (current) {
                struct ares_srv_reply *next = current->next;
                if (current->host) {
                    ares_free_string(current->host);
                }
                ares_free_string(current);
                current = next;
            }
        }
    }
    
    // Setup a dummy channel for ares_send (this would normally be initialized properly)
    ares_channel channel = NULL;
    int channel_init_result = ares_init(&channel);
    
    if (channel && query_buf && query_len > 0) {
        // Define a simple callback for ares_send
        auto dummy_callback = [](void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
            // Callback implementation - just ignore for fuzzing
        };
        
        // Call ares_send if we have a valid channel and query
        ares_send(channel, query_buf, query_len, dummy_callback, NULL);
    }
    
    // Cleanup allocated resources
    if (query_buf) {
        ares_free_string(query_buf);
    }
    
    if (mkquery_buf) {
        ares_free_string(mkquery_buf);
    }
    
    if (channel) {
        ares_destroy(channel);
    }
    
    free(domain_name);
    
    return 0;
}
