#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Callback function for ares_search
static void search_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // In a real application, this would process the result
    // For fuzzing purposes, we just store the result
    *(int*)arg = status; // Store status to avoid unused variable warning
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_channel channel = NULL;
    unsigned char *query_buf = NULL;
    int query_buflen = 0;
    struct ares_mx_reply *mx_out = NULL;
    int search_result = 0;
    
    // Limit input size to prevent excessive memory allocation
    if (size < 10 || size > 1024) {
        return 0;
    }
    
    // Create a null-terminated string from input data for domain name
    // Ensure we have enough data for a minimal domain name
    if (size < 5) {
        return 0;
    }
    
    // Copy input data to make it null-terminated
    char *domain_name = (char *)malloc(size + 1);
    if (!domain_name) {
        return 0;
    }
    
    memcpy(domain_name, data, size);
    domain_name[size] = '\0';
    
    // Replace any null bytes in the middle of the string with valid characters
    for (size_t i = 0; i < size; i++) {
        if (domain_name[i] == '\0') {
            domain_name[i] = 'a';
        }
    }
    
    // Initialize ares channel
    int init_result = ares_init(&channel);
    if (init_result != ARES_SUCCESS) {
        free(domain_name);
        return 0;
    }
    
    // Use part of input for DNS query parameters
    int dnsclass = ARES_CLASS_IN;
    int type = ARES_REC_TYPE_MX;
    unsigned short id = 0;
    int rd = 1;
    
    // Extract some values from input data if possible
    if (size >= 4) {
        id = (data[0] << 8) | data[1];
        dnsclass = data[2] % 256;
        type = data[3] % 256;
        
        // Ensure valid range for DNS classes and types
        if (dnsclass == 0) dnsclass = ARES_CLASS_IN;
        if (type == 0) type = ARES_REC_TYPE_MX;
    }
    
    // Create a DNS query
    int mkquery_result = ares_mkquery(domain_name, dnsclass, type, id, rd, &query_buf, &query_buflen);
    if (mkquery_result == ARES_SUCCESS && query_buf && query_buflen > 0) {
        // Perform a search operation
        ares_search(channel, domain_name, dnsclass, type, search_callback, &search_result);
        
        // Process the channel (this simulates the event loop)
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        ares_process(channel, &read_fds, &write_fds);
        
        // Parse MX reply if we have valid response data
        // For fuzzing, we'll try to parse the query buffer as if it was a response
        if (query_buflen >= HFIXEDSZ) { // HFIXEDSZ is header size
            int parse_result = ares_parse_mx_reply(query_buf, query_buflen, &mx_out);
            if (parse_result == ARES_SUCCESS && mx_out) {
                // Free the parsed data
                ares_free_data(mx_out);
                mx_out = NULL;
            }
        }
    }
    
    // Clean up allocated resources
    if (query_buf) {
        ares_free_string(query_buf);
        query_buf = NULL;
    }
    
    if (channel) {
        ares_destroy(channel);
        channel = NULL;
    }
    
    free(domain_name);
    
    return 0;
}
