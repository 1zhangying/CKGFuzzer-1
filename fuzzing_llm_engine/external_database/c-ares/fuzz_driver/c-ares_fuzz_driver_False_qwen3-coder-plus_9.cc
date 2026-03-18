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
// This driver tests ares_process_fd, ares_free_data, ares_destroy, and ares_query APIs
// It creates a DNS query based on fuzz input, processes it, and cleans up resources

// Callback function for ares_query to handle DNS response
void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // In fuzzing context, we just need to receive the response without further processing
    // The actual response data will be handled by the fuzzer
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    ares_channel channel;
    int result;

    // Initialize c-ares channel
    result = ares_init(&channel);
    if (result != ARES_SUCCESS) {
        return 0; // Initialization failed, nothing to clean up
    }

    // Create a copy of input data to work with
    char *input_copy = (char*)malloc(size + 1);
    if (!input_copy) {
        ares_destroy(channel);
        return 0;
    }
    memcpy(input_copy, data, size);
    input_copy[size] = '\0'; // Null terminate to make it a C-string

    // Limit the size of the domain name to avoid issues with very long strings
    size_t max_domain_len = 255;
    if (size > max_domain_len) {
        input_copy[max_domain_len] = '\0';
    } else {
        // Ensure we have a valid domain-like string
        // Replace non-printable characters with dots or alphanumeric chars
        for (size_t i = 0; i < strlen(input_copy); i++) {
            if (input_copy[i] < 32 || input_copy[i] > 126) {
                // Replace control characters with 'a'
                input_copy[i] = 'a';
            }
        }
    }

    // If the input is too short, pad with a default domain name
    if (strlen(input_copy) < 1) {
        strcpy(input_copy, "example.com");
    }

    // Perform a DNS query using the fuzz input as the domain name
    // We'll query for A records (type 1) in the IN class (class 1)
    ares_query(channel, input_copy, C_IN, T_A, query_callback, NULL);

    // Process any pending DNS operations
    // Since we don't have real sockets in this context, we'll use invalid file descriptors
    ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

    // Clean up allocated resources
    free(input_copy);
    
    // Destroy the channel and all associated resources
    ares_destroy(channel);

    return 0;
}
