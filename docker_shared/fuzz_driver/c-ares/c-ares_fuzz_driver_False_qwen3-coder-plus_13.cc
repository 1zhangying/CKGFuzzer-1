#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Callback function for ares_query
void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // In fuzzing context, we just need to handle the callback without crashing
    // The actual processing depends on the query type and result
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)abuf;
    (void)alen;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize the c-ares library
    int init_result = ares_library_init(ARES_LIB_INIT_ALL);
    if (init_result != ARES_SUCCESS) {
        return 0;
    }

    // Initialize ares channel
    ares_channel channel;
    int result = ares_init(&channel);
    if (result != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    // Prepare DNS query parameters from fuzz input
    // We'll extract a portion of the input as the domain name to query
    size_t max_domain_len = size > 255 ? 255 : size;
    if (max_domain_len == 0) {
        ares_destroy(channel);
        ares_library_cleanup();
        return 0;
    }

    // Copy domain name from fuzz input
    char *domain_name = (char*)malloc(max_domain_len + 1);
    if (!domain_name) {
        ares_destroy(channel);
        ares_library_cleanup();
        return 0;
    }

    memcpy(domain_name, data, max_domain_len);
    domain_name[max_domain_len] = '\0';

    // Advance data pointer to get class and type
    const uint8_t *ptr = data + max_domain_len;
    size_t remaining_size = size - max_domain_len;

    // Extract DNS class and type from remaining input if available
    int dns_class = C_IN;  // Default to Internet class
    int dns_type = T_A;    // Default to A record type

    if (remaining_size >= sizeof(uint16_t)) {
        uint16_t temp_class = *(uint16_t*)ptr;
        dns_class = temp_class % 65536;  // Ensure valid range
        ptr += sizeof(uint16_t);
        remaining_size -= sizeof(uint16_t);
    }

    if (remaining_size >= sizeof(uint16_t)) {
        uint16_t temp_type = *(uint16_t*)ptr;
        dns_type = temp_type % 65536;  // Ensure valid range
    }

    // Perform DNS query
    ares_query(channel, domain_name, dns_class, dns_type, query_callback, NULL);

    // Process file descriptors - simulate activity
    // Use ARES_SOCKET_BAD to indicate no actual sockets
    ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

    // Clean up
    free(domain_name);
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}
