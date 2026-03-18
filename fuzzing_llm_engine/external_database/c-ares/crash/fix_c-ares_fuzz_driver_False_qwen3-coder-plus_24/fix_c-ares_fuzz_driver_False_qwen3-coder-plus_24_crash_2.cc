#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Global channel for the fuzzer
static ares_channel channel = nullptr;

// Structure to hold context for the callback
struct FuzzContext {
    int call_count;
    int expected_calls;
};

// Callback function for DNS queries
void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // Do nothing - just receive the response
    (void)status;
    (void)timeouts;
    (void)abuf;
    (void)alen;
    
    if (arg) {
        FuzzContext *ctx = static_cast<FuzzContext*>(arg);
        ctx->call_count++;
    }
}

// Initialize c-ares if not already done
int init_cares() {
    if (channel == nullptr) {
        struct ares_options options;
        int optmask = 0;
        
        int result = ares_init_options(&channel, &options, optmask);
        if (result != ARES_SUCCESS) {
            return result;
        }
    }
    return ARES_SUCCESS;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {  // Need minimum data for basic operation
        return 0;
    }
    
    // Initialize c-ares
    if (init_cares() != ARES_SUCCESS) {
        return 0;
    }
    
    // Create a copy of data to work with and ensure null termination for string operations
    uint8_t* data_copy = static_cast<uint8_t*>(malloc(size + 1));
    if (!data_copy) {
        return 0;
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';
    
    // Extract different parts of the data for different parameters
    size_t offset = 0;
    
    // Get a name string from the data (first part)
    size_t name_len = 1 + (data_copy[offset] % 10);  // 1-10 characters for name
    if (offset + name_len > size) {
        name_len = size - offset;
    }
    if (name_len == 0) {
        free(data_copy);
        return 0;
    }
    
    char* name = static_cast<char*>(malloc(name_len + 1));
    if (!name) {
        free(data_copy);
        return 0;
    }
    
    memcpy(name, data_copy + offset, name_len);
    name[name_len] = '\0';
    offset += name_len;
    
    // Validate name contains only valid characters for a domain name
    for (size_t i = 0; i < name_len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || 
              (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || 
              c == '-' || c == '.')) {
            name[i] = 'x';  // Replace invalid character
        }
    }
    
    // Ensure name doesn't end with a dot to prevent issues
    while (strlen(name) > 0 && name[strlen(name)-1] == '.') {
        name[strlen(name)-1] = '\0';
    }
    
    if (strlen(name) == 0) {
        strcpy(name, "example");
    }
    
    // Get class and type from remaining data
    int dnsclass = C_IN;  // Default to Internet class (using standard DNS constant instead of ARES_CLASS_IN)
    int type = T_A;    // Default to A record (using standard DNS constant instead of ARES_REC_TYPE_A)
    
    if (offset + 2 <= size) {
        dnsclass = data_copy[offset] % 256;
        type = data_copy[offset + 1] % 256;
        offset += 2;
    }
    
    // Limit the class and type to valid ranges to avoid errors
    if (dnsclass < 1 || dnsclass > 254) {
        dnsclass = C_IN;  // Use standard DNS constant
    }
    if (type < 1 || type > 255) {
        type = T_A;  // Use standard DNS constant
    }
    
    // Create context for the callback
    FuzzContext ctx;
    ctx.call_count = 0;
    ctx.expected_calls = 0;
    
    // Call ares_query
    ares_query(channel, name, dnsclass, type, query_callback, &ctx);
    ctx.expected_calls++;
    
    // Call ares_search with same parameters
    ares_search(channel, name, dnsclass, type, query_callback, &ctx);
    ctx.expected_calls++;
    
    // Call ares_process_fd with invalid file descriptors to test error handling
    ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    
    // Process any pending DNS operations
    fd_set readers, writers;
    FD_ZERO(&readers);
    FD_ZERO(&writers);
    
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000; // 10ms timeout
    
    // Process the channel with timeout
    ares_process(channel, &readers, &writers);
    
    // Clean up allocated memory
    free(name);
    free(data_copy);
    
    return 0;
}
