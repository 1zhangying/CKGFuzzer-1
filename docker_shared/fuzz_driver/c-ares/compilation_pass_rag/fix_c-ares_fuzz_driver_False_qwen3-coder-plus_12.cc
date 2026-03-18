#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Structure to hold callback context during fuzzing
struct FuzzCallbackContext {
    int status;
    int timeouts;
    std::string result_data;
};

// Static variable to hold context during fuzzing session
static FuzzCallbackContext g_callback_context;

// Callback function for ares_query
static void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    FuzzCallbackContext *ctx = static_cast<FuzzCallbackContext*>(arg);
    if (ctx) {
        ctx->status = status;
        ctx->timeouts = timeouts;
        if (abuf && alen > 0) {
            // Store result data for potential later use
            ctx->result_data.assign(reinterpret_cast<const char*>(abuf), alen);
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    ares_channel channel = nullptr;
    int init_result = ares_init(&channel);
    
    if (init_result != ARES_SUCCESS || !channel) {
        // Even if init fails, we might have partial initialization
        if (channel) {
            ares_destroy(channel);
        }
        return 0;
    }

    // Initialize our callback context
    memset(&g_callback_context, 0, sizeof(g_callback_context));

    // Extract a domain name from the input data
    // We'll use the first portion of the data as a potential domain name
    size_t domain_len = 0;
    if (size > 0) {
        // Use first byte to determine domain length (max 63 chars to keep it reasonable)
        domain_len = (data[0] % 64);
        if (domain_len >= size) {
            domain_len = (size > 1) ? size - 1 : 0;
        } else if (domain_len == 0) {
            domain_len = 1;  // At least one character
        }
    }

    if (domain_len > 0) {
        // Create a null-terminated domain string
        char *domain_name = static_cast<char*>(malloc(domain_len + 1));
        if (domain_name) {
            memcpy(domain_name, data + 1, domain_len);
            domain_name[domain_len] = '\0';

            // Sanitize the domain name to contain only valid characters
            for (size_t i = 0; i < domain_len; ++i) {
                if ((domain_name[i] >= 'a' && domain_name[i] <= 'z') ||
                    (domain_name[i] >= 'A' && domain_name[i] <= 'Z') ||
                    (domain_name[i] >= '0' && domain_name[i] <= '9') ||
                    domain_name[i] == '-' || domain_name[i] == '.') {
                    continue;
                } else {
                    domain_name[i] = 'x'; // Replace invalid chars
                }
            }

            // Determine query parameters from remaining data
            // Use standard DNS constants from ares_nameser.h
            int dns_class = C_IN; // Standard internet class - was ARES_CLASS_IN
            int query_type = T_A; // Standard A record - was ARES_REC_TYPE_A
            
            // Use more input bytes to determine query type if available
            if (size > domain_len + 1) {
                // Map the input byte to a valid DNS record type range
                // Common DNS record types range from 1 to 255, so we'll limit it appropriately
                unsigned char type_byte = data[domain_len + 1];
                switch(type_byte % 10) { // Use modulo to select from common types
                    case 0: query_type = T_A; break;
                    case 1: query_type = T_NS; break;
                    case 2: query_type = T_CNAME; break;
                    case 3: query_type = T_SOA; break;
                    case 4: query_type = T_PTR; break;
                    case 5: query_type = T_MX; break;
                    case 6: query_type = T_TXT; break;
                    case 7: query_type = T_AAAA; break;
                    case 8: query_type = T_SRV; break;
                    case 9: query_type = T_ANY; break;
                }
            }

            // Perform the query
            ares_query(channel, domain_name, dns_class, query_type, query_callback, &g_callback_context);

            // Process the query - this would normally require actual network activity
            // In a fuzzing context, we just call it to exercise the code path
            fd_set read_fds, write_fds;
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            
            // Call ares_process to simulate processing
            ares_process(channel, &read_fds, &write_fds);

            free(domain_name);
        }
    }

    // Clean up the channel
    ares_destroy(channel);

    // Perform library cleanup
    ares_library_cleanup();

    return 0;
}
