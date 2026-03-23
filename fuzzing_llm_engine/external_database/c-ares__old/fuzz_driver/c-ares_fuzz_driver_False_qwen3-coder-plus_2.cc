#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation to test c-ares library cleanup functions
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize the ares library if not already initialized
    int init_result = ares_library_init(ARES_LIB_INIT_ALL);
    
    // If library initialization failed, return early
    if (init_result != ARES_SUCCESS) {
        return 0;
    }
    
    // Perform bounds checking for minimum required size
    if (size < sizeof(int)) {
        ares_library_cleanup();
        return 0;
    }
    
    // Extract control parameters from input data
    size_t offset = 0;
    int mode = 0;
    if (size >= sizeof(int)) {
        mode = *(const int*)data;
        offset = sizeof(int);
    }
    
    // Test different cleanup functions based on input mode
    switch (abs(mode) % 5) {
        case 0: {
            // Test ares_free_data with dummy allocated data
            // Since we can't easily create valid parsed data without parsing actual DNS replies,
            // we'll just call the function with NULL to ensure it doesn't crash
            ares_free_data(NULL);
            break;
        }
        
        case 1: {
            // Test ares_free_string
            if (offset + 10 <= size) {
                // Allocate a string based on input data
                char *test_str = (char*)malloc(11);
                if (test_str) {
                    memcpy(test_str, data + offset, 10);
                    test_str[10] = '\0';  // Null terminate
                    ares_free_string(test_str);
                }
            } else {
                // Call with NULL to ensure it doesn't crash
                ares_free_string(NULL);
            }
            break;
        }
        
        case 2: {
            // Test ares_free_hostent
            struct hostent *host = NULL;
            
            // Create a minimal hostent structure to test cleanup
            host = (struct hostent*)malloc(sizeof(struct hostent));
            if (host) {
                // Initialize the hostent structure
                memset(host, 0, sizeof(struct hostent));
                
                // Allocate and initialize some fields to simulate a real structure
                char *hostname = (char*)malloc(10);
                if (hostname) {
                    strncpy(hostname, "example", 9);
                    hostname[9] = '\0';
                    host->h_name = hostname;
                }
                
                // Allocate aliases array
                char **aliases = (char**)malloc(2 * sizeof(char*));
                if (aliases) {
                    char *alias1 = (char*)malloc(10);
                    if (alias1) {
                        strncpy(alias1, "alias1", 9);
                        alias1[9] = '\0';
                        aliases[0] = alias1;
                    }
                    aliases[1] = NULL;
                    host->h_aliases = aliases;
                }
                
                // Allocate address list
                char **addr_list = (char**)malloc(2 * sizeof(char*));
                if (addr_list) {
                    char *addr = (char*)malloc(4); // IPv4 address size
                    if (addr) {
                        addr[0] = 192;
                        addr[1] = 168;
                        addr[2] = 1;
                        addr[3] = 1;
                        addr_list[0] = addr;
                    }
                    addr_list[1] = NULL;
                    host->h_addr_list = addr_list;
                }
                
                // Call the cleanup function
                ares_free_hostent(host);
            } else {
                // Call with NULL to ensure it doesn't crash
                ares_free_hostent(NULL);
            }
            break;
        }
        
        case 3: {
            // Test ares_destroy by creating and destroying a channel
            ares_channel channel;
            int status = ares_init(&channel);
            
            if (status == ARES_SUCCESS) {
                // Use the channel for basic operations if desired
                // For this fuzzer, we'll just destroy it immediately
                
                // Call the cleanup function
                ares_destroy(channel);
            }
            break;
        }
        
        case 4: {
            // Test multiple cleanup functions together
            ares_free_data(NULL);  // Safe to call with NULL
            
            if (offset + 5 <= size) {
                char *test_str = (char*)malloc(6);
                if (test_str) {
                    memcpy(test_str, data + offset, 5);
                    test_str[5] = '\0';
                    ares_free_string(test_str);
                }
            } else {
                ares_free_string(NULL);
            }
            
            // Create and destroy a channel
            ares_channel channel;
            int status = ares_init(&channel);
            if (status == ARES_SUCCESS) {
                ares_destroy(channel);
            }
            
            // Clean up a hostent
            ares_free_hostent(NULL);
            break;
        }
    }
    
    // Perform library cleanup
    ares_library_cleanup();
    
    return 0;
}
