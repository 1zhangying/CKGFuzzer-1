#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Global flag to track library initialization state
static bool library_initialized = false;

// Structure to hold context for the callback
struct FuzzContext {
    const uint8_t *data;
    size_t size;
    volatile int completed;
};

// Callback function for ares_query
void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // Mark query as completed
    struct FuzzContext *ctx = (struct FuzzContext *)arg;
    ctx->completed = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize library only once
    if (!library_initialized) {
        int lib_init_result = ares_library_init(0);  // Initialize without special flags
        if (lib_init_result != ARES_SUCCESS) {
            return 0;  // Exit early if library init fails
        }
        library_initialized = true;
    }

    // Early exit if there's not enough data to work with
    if (size < 4) {
        return 0;
    }

    ares_channel channel;
    int init_result = ares_init(&channel);
    
    if (init_result != ARES_SUCCESS) {
        return 0;  // Initialization failed, exit gracefully
    }

    // Prepare context for the callback
    struct FuzzContext ctx;
    ctx.data = data;
    ctx.size = size;
    ctx.completed = 0;

    // Extract a portion of the input data to form a potential domain name
    // Limit the domain length to a reasonable value
    size_t domain_len = size > 0 ? (data[0] % 254) + 1 : 0;  // At least 1 byte for valid char
    if (domain_len >= size) {
        domain_len = size - 1;
    }
    
    if (domain_len == 0) {
        ares_destroy(channel);
        return 0;
    }

    // Create a null-terminated domain string from input data
    char *domain_name = (char *)malloc(domain_len + 1);
    if (!domain_name) {
        ares_destroy(channel);
        return 0;
    }

    // Copy bytes ensuring they are printable characters (a-z, A-Z, 0-9, hyphen, dot)
    for (size_t i = 0; i < domain_len; i++) {
        unsigned char c = data[i+1]; // Skip first byte to use remaining data
        if ((c >= 'a' && c <= 'z') || 
            (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || 
            c == '-' || c == '.') {
            domain_name[i] = c;
        } else {
            // Map other characters to a safe range
            domain_name[i] = 'a' + (c % 26);
        }
    }
    domain_name[domain_len] = '\0';

    // Parse additional parameters from input data
    int dns_class = C_IN;  // Use standard DNS constant instead of ARES_CLASS_IN
    int query_type = T_A;  // Use standard DNS constant instead of ARES_REC_TYPE_A
    
    if (size > 1) {
        // Limit to a few common classes using standard DNS constants
        int class_val = data[1] % 3;
        switch(class_val) {
            case 0: dns_class = C_IN; break;   // Internet class
            case 1: dns_class = C_CHAOS; break; // Chaos class  
            case 2: dns_class = C_HS; break;   // Hesiod class
        }
    }
    
    if (size > 2) {
        // Select a reasonable query type based on input data using standard DNS constants
        int type_val = data[2] % 10;
        switch(type_val) {
            case 0: query_type = T_A; break;         // Use T_A instead of ARES_REC_TYPE_A
            case 1: query_type = T_NS; break;        // Use T_NS instead of ARES_REC_TYPE_NS
            case 2: query_type = T_CNAME; break;     // Use T_CNAME instead of ARES_REC_TYPE_CNAME
            case 3: query_type = T_SOA; break;       // Use T_SOA instead of ARES_REC_TYPE_SOA
            case 4: query_type = T_PTR; break;       // Use T_PTR instead of ARES_REC_TYPE_PTR
            case 5: query_type = T_MX; break;        // Use T_MX instead of ARES_REC_TYPE_MX
            case 6: query_type = T_TXT; break;       // Use T_TXT instead of ARES_REC_TYPE_TXT
            case 7: query_type = T_AAAA; break;      // Use T_AAAA instead of ARES_REC_TYPE_AAAA
            case 8: query_type = T_SRV; break;       // Use T_SRV instead of ARES_REC_TYPE_SRV
            case 9: query_type = T_ANY; break;       // Use T_ANY instead of ARES_REC_TYPE_ANY
        }
    }

    // Perform the DNS query
    ares_query(channel, domain_name, dns_class, query_type, query_callback, &ctx);

    // Process the query - simulate some I/O activity
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    
    // Add some file descriptors if available (in fuzzing context, these might not be real sockets)
    // In a real application, we'd add actual socket descriptors here
    ares_process(channel, &read_fds, &write_fds);

    // Clean up
    free(domain_name);
    ares_destroy(channel);

    return 0;
}
