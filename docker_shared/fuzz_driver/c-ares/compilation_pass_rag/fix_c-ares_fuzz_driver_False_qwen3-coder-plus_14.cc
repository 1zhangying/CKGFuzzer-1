#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Callback function for ares_search to capture results
static void search_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // This is a simple callback that just records the result
    // In real usage, this would process the DNS response
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)abuf;
    (void)alen;
}

// Fuzz driver entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    ares_channel channel = nullptr;
    unsigned char *query_buf = nullptr;
    int query_buflen = 0;
    struct hostent *hostent_ptr = nullptr;
    struct ares_addrttl addrttls[10]; // Fixed-size array for address TTLs
    int naddrttls = 10; // Number of entries in addrttls array
    
    // Early exit if input is too small
    if (size < 10) {
        return 0;
    }
    
    // Initialize c-ares channel
    int init_result = ares_init(&channel);
    if (init_result != ARES_SUCCESS || channel == nullptr) {
        return 0; // Initialization failed, nothing more to do
    }
    
    // Extract parameters from fuzz data for ares_mkquery
    // We'll use the first few bytes to determine query parameters
    size_t offset = 0;
    
    // Determine DNS class (first byte after initial offset)
    int dns_class = C_IN; // Default value - Changed from ARES_CLASS_IN to C_IN
    if (offset < size) {
        dns_class = data[offset] % 256; // Keep within valid range
        offset++;
    }
    
    // Determine query type (second byte)
    int query_type = T_A; // Default to A record
    if (offset < size) {
        // Map to common DNS types
        switch (data[offset] % 10) {  // Limit to 10 different types
            case 0: query_type = T_A; break;
            case 1: query_type = T_NS; break;
            case 2: query_type = T_CNAME; break;
            case 3: query_type = T_SOA; break;
            case 4: query_type = T_PTR; break;
            case 5: query_type = T_MX; break;
            case 6: query_type = T_TXT; break;
            case 7: query_type = T_AAAA; break;
            case 8: query_type = T_SRV; break;
            case 9: query_type = T_OPT; break;
        }
        offset++;
    }
    
    // Determine recursion desired flag
    int recursion_desired = 1; // Default to true
    if (offset < size) {
        recursion_desired = data[offset] % 2; // 0 or 1
        offset++;
    }
    
    // Create a null-terminated string from remaining data for domain name
    // Make sure we have enough data left for a reasonable domain name
    if (offset >= size) {
        ares_destroy(channel);
        return 0;
    }
    
    size_t remaining_size = size - offset;
    if (remaining_size == 0) {
        ares_destroy(channel);
        return 0;
    }
    
    // Limit domain name length to prevent overly long strings
    size_t domain_len = remaining_size > 255 ? 255 : remaining_size;
    char *domain_name = (char*)malloc(domain_len + 1);
    if (!domain_name) {
        ares_destroy(channel);
        return 0;
    }
    
    // Copy data to domain name and null terminate
    memcpy(domain_name, data + offset, domain_len);
    
    // Sanitize domain name to contain only valid characters
    for (size_t i = 0; i < domain_len; i++) {
        unsigned char c = (unsigned char)domain_name[i];
        if ((c >= 'a' && c <= 'z') || 
            (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || 
            c == '.' || c == '-' || c == '_') {
            continue; // Valid character
        } else {
            domain_name[i] = '.'; // Replace invalid with dot
        }
    }
    domain_name[domain_len] = '\0';
    
    // Ensure domain name is not empty
    if (strlen(domain_name) == 0) {
        strcpy(domain_name, "example.com");
    }
    
    // Call ares_mkquery to create a DNS query
    int mkquery_result = ares_mkquery(
        domain_name,      // Domain name
        dns_class,        // DNS class
        query_type,       // Query type
        1234,             // ID (arbitrary)
        recursion_desired,// Recursion desired flag
        &query_buf,       // Output buffer
        &query_buflen     // Output buffer length
    );
    
    if (mkquery_result == ARES_SUCCESS && query_buf != nullptr && query_buflen > 0) {
        // Test ares_parse_a_reply with the generated query (this might not be a valid reply but tests the function)
        // Note: We're passing the query as if it were a reply - this is for testing purposes
        int parse_result = ares_parse_a_reply(
            query_buf,           // Buffer containing reply
            query_buflen,        // Length of reply
            &hostent_ptr,        // Output hostent structure
            addrttls,            // Array of address TTLs
            &naddrttls           // Number of addresses in array
        );
        
        // Clean up hostent if allocated
        if (parse_result == ARES_SUCCESS && hostent_ptr != nullptr) {
            // Free the hostent structure
            free(hostent_ptr->h_addr_list);  // Free address list
            free(hostent_ptr->h_aliases);    // Free aliases
            free(hostent_ptr);               // Free main structure
            hostent_ptr = nullptr;
        }
        
        // Free the query buffer using standard free() instead of ares_free
        free(query_buf);  // Changed from ares_free to free
        query_buf = nullptr;
    }
    
    // Call ares_search to initiate a search operation
    ares_search(
        channel,              // Channel
        domain_name,          // Name to search
        dns_class,            // Class
        query_type,           // Type
        search_callback,      // Callback function
        nullptr               // User data for callback
    );
    
    // Create dummy fd_sets for ares_process
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    
    // Call ares_process to process any pending operations
    ares_process(channel, &read_fds, &write_fds);
    
    // Clean up resources
    free(domain_name);
    if (channel) {
        ares_destroy(channel);
    }
    
    return 0;
}
