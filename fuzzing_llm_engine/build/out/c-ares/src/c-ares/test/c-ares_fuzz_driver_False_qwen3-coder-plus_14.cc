#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for testing c-ares library functions
// This driver tests the following APIs: ares_process_fd, ares_mkquery, 
// ares_parse_aaaa_reply, ares_send, ares_create_query, ares_parse_a_reply

// Callback function for ares_send
static void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // In fuzzing context, just acknowledge the callback
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)abuf;
    (void)alen;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0; // Need at least some data to work with
    }

    ares_channel channel = nullptr;
    
    // Initialize ares channel
    int result = ares_init(&channel);
    if (result != ARES_SUCCESS || channel == nullptr) {
        return 0;
    }

    // Extract data segments for different API calls
    size_t offset = 0;
    
    // Extract domain name (null-terminated string) - minimum 1 char + null terminator
    if (offset >= size || data[offset] == 0) {
        ares_destroy(channel);
        return 0;
    }
    
    size_t domain_len = 0;
    for (size_t i = offset; i < size && data[i] != 0; i++) {
        domain_len++;
    }
    
    if (domain_len == 0 || offset + domain_len >= size) {
        ares_destroy(channel);
        return 0;
    }
    
    char *domain_name = (char*)malloc(domain_len + 1);
    if (!domain_name) {
        ares_destroy(channel);
        return 0;
    }
    
    memcpy(domain_name, data + offset, domain_len);
    domain_name[domain_len] = '\0';
    offset += domain_len + 1;
    
    // Validate domain name format to prevent bad names
    bool valid_domain = true;
    for (size_t i = 0; i < domain_len; i++) {
        if (domain_name[i] == '.') {
            if (i == 0 || i == domain_len - 1 || domain_name[i+1] == '.') {
                valid_domain = false;
                break;
            }
        } else if (!((domain_name[i] >= 'a' && domain_name[i] <= 'z') ||
                    (domain_name[i] >= 'A' && domain_name[i] <= 'Z') ||
                    (domain_name[i] >= '0' && domain_name[i] <= '9') ||
                    domain_name[i] == '-')) {
            valid_domain = false;
            break;
        }
    }
    
    if (!valid_domain) {
        free(domain_name);
        ares_destroy(channel);
        return 0;
    }

    // Test ares_create_query
    unsigned char *query_buf = nullptr;
    int query_buflen = 0;
    unsigned short query_id = 1234; // arbitrary ID
    
    // Determine DNS class and type from available data
    int dns_class = C_IN; // Internet class
    int dns_type = T_A; // A record type (IPv4)
    
    if (offset + 1 < size) {
        dns_class = 1 + (data[offset] % 255); // Ensure valid class range
        dns_type = 1 + (data[offset + 1] % 255); // Ensure valid type range
        offset += 2;
    }
    
    result = ares_create_query(
        domain_name, 
        dns_class, 
        dns_type, 
        query_id, 
        1,  // recursion desired
        &query_buf, 
        &query_buflen, 
        0   // max_udp_size
    );
    
    if (result == ARES_SUCCESS && query_buf != nullptr && query_buflen > 0) {
        // Test ares_mkquery - alternative way to create query
        unsigned char *mkquery_buf = nullptr;
        int mkquery_buflen = 0;
        
        result = ares_mkquery(
            domain_name,
            dns_class,
            dns_type,
            query_id,
            1,  // recursion desired
            &mkquery_buf,
            &mkquery_buflen
        );
        
        if (result == ARES_SUCCESS && mkquery_buf != nullptr) {
            // Test ares_send with the created query
            ares_send(channel, mkquery_buf, mkquery_buflen, query_callback, nullptr);
            
            // Clean up mkquery buffer
            ares_free_string(mkquery_buf);
        }
        
        // Test ares_send with original query buffer
        ares_send(channel, query_buf, query_buflen, query_callback, nullptr);
        
        // Clean up original query buffer
        ares_free_string(query_buf);
    } else {
        // If query creation failed, try with default values
        unsigned char *default_query = nullptr;
        int default_buflen = 0;
        
        result = ares_create_query(
            "example.com", 
            C_IN, 
            T_A, 
            1234, 
            1, 
            &default_query, 
            &default_buflen, 
            0
        );
        
        if (result == ARES_SUCCESS && default_query != nullptr && default_buflen > 0) {
            ares_send(channel, default_query, default_buflen, query_callback, nullptr);
            ares_free_string(default_query);
        }
    }

    // Test ares_process_fd - this requires file descriptors which we can't control in fuzzing
    // We'll pass invalid file descriptors to avoid actual processing
    ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

    // Test parsing functions with fake data if we have enough remaining bytes
    if (offset + 20 < size) { // Need sufficient data for a fake DNS response
        // Create a minimal fake DNS response for A record
        unsigned char fake_a_response[64];
        memset(fake_a_response, 0, sizeof(fake_a_response));
        
        // Copy available data to avoid uninitialized access
        size_t copy_size = (sizeof(fake_a_response) < (size - offset)) ? 
                           sizeof(fake_a_response) : (size - offset);
        memcpy(fake_a_response, data + offset, copy_size);
        
        // Set response bit and some basic flags
        fake_a_response[2] |= 0x80; // QR bit (response)
        fake_a_response[3] |= 0x00; // No error
        
        // Test ares_parse_a_reply
        struct hostent *host = nullptr;
        struct ares_addrttl addrttls[5]; // Array to store address-TTL pairs
        int naddrttls = 5;
        
        result = ares_parse_a_reply(
            fake_a_response, 
            sizeof(fake_a_response), 
            &host, 
            addrttls, 
            &naddrttls
        );
        
        // Clean up parsed hostent if created
        if (host != nullptr) {
            ares_free_hostent(host);
        }
        
        // Test ares_parse_aaaa_reply with same fake data
        struct hostent *host6 = nullptr;
        struct ares_addr6ttl addr6ttls[5];
        int naddr6ttls = 5;
        
        result = ares_parse_aaaa_reply(
            fake_a_response, 
            sizeof(fake_a_response), 
            &host6, 
            addr6ttls, 
            &naddr6ttls
        );
        
        // Clean up parsed hostent if created
        if (host6 != nullptr) {
            ares_free_hostent(host6);
        }
    }

    // Clean up resources
    free(domain_name);
    ares_destroy(channel);
    
    return 0;
}
