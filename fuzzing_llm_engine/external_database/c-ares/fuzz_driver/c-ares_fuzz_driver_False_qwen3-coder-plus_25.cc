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
// This driver tests ares_process, ares_process_fd, ares_mkquery, 
// ares_send, ares_create_query, and ares_query functions

// Callback function for ares operations
void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // Do nothing - just satisfy the callback requirement
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)abuf;
    (void)alen;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {  // Need minimum data for basic operations
        return 0;
    }

    ares_channel channel = NULL;
    int result;
    
    // Initialize the c-ares channel
    result = ares_init(&channel);
    if (result != ARES_SUCCESS || channel == NULL) {
        return 0;
    }

    // Extract parameters from fuzz data with bounds checking
    size_t offset = 0;
    
    // Get DNS class from fuzz data
    int dns_class = ARES_CLASS_IN;  // Default value
    if (offset + sizeof(int) <= size) {
        dns_class = *((const int*)(data + offset)) % 65536;  // Limit to valid range
        offset += sizeof(int);
    }
    
    // Get DNS type from fuzz data
    int dns_type = ARES_REC_TYPE_A;  // Default value
    if (offset + sizeof(int) <= size) {
        dns_type = *((const int*)(data + offset)) % 65536;  // Limit to valid range
        offset += sizeof(int);
    }
    
    // Get recursion flag from fuzz data
    int recursion_flag = 1;  // Default to recursive
    if (offset + sizeof(int) <= size) {
        recursion_flag = *((const int*)(data + offset)) % 2;
        offset += sizeof(int);
    }
    
    // Get ID from fuzz data
    unsigned short query_id = 1;  // Default value
    if (offset + sizeof(unsigned short) <= size) {
        query_id = *((const unsigned short*)(data + offset));
        offset += sizeof(unsigned short);
    }
    
    // Extract domain name from remaining data
    const size_t min_name_len = 1;
    const size_t max_name_len = 255;
    size_t name_len = 0;
    
    if (offset < size) {
        name_len = (size - offset) % max_name_len;
        if (name_len < min_name_len) {
            name_len = min_name_len;
        }
        
        // Make sure name is null-terminated and valid
        char *domain_name = (char*)malloc(name_len + 1);
        if (domain_name) {
            memcpy(domain_name, data + offset, name_len);
            domain_name[name_len] = '\0';
            
            // Replace potentially problematic characters to avoid invalid names
            for (size_t i = 0; i < name_len; i++) {
                if (domain_name[i] == '\0' || domain_name[i] == '.') {
                    domain_name[i] = 'x';  // Replace with safe character
                }
            }
            
            // Test ares_create_query
            unsigned char *query_buf = NULL;
            int query_buflen = 0;
            result = ares_create_query(domain_name, dns_class, dns_type, query_id, 
                                       recursion_flag, &query_buf, &query_buflen, 0);
            if (result == ARES_SUCCESS && query_buf != NULL && query_buflen > 0) {
                
                // Test ares_mkquery (which internally uses ares_create_query)
                unsigned char *mkquery_buf = NULL;
                int mkquery_buflen = 0;
                result = ares_mkquery(domain_name, dns_class, dns_type, query_id, 
                                      recursion_flag, &mkquery_buf, &mkquery_buflen);
                if (result == ARES_SUCCESS && mkquery_buf != NULL) {
                    ares_free_string(mkquery_buf);
                }
                
                // Test ares_send
                ares_send(channel, query_buf, query_buflen, query_callback, NULL);
                
                // Test ares_query
                ares_query(channel, domain_name, dns_class, dns_type, query_callback, NULL);
                
                ares_free_string(query_buf);
            }
            
            free(domain_name);
        }
    }
    
    // Prepare FD sets for ares_process
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    
    // Test ares_process with empty fd sets
    ares_process(channel, &read_fds, &write_fds);
    
    // Test ares_process_fd with bad sockets
    ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    
    // Clean up the channel
    ares_destroy(channel);
    
    return 0;
}
