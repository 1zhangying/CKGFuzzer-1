#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing lcms2 APIs: cmsReadTag, cmsIT8Free, cmsOpenProfileFromMem, cmsIT8LoadFromMem, cmsIT8SaveToMem, cmsWriteTag
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if size is too small to process anything meaningful
    if (size < 16) {
        return 0;
    }

    // Split the input data into different sections for various operations
    size_t profile_size = size / 3;
    if (profile_size < 16) profile_size = 16;
    if (profile_size > size) profile_size = size;
    
    size_t it8_data_size = (size - profile_size) / 2;
    if (it8_data_size < 16) it8_data_size = 16;
    size_t remaining_size = size - profile_size - it8_data_size;
    
    // Extract sections of data for different purposes
    const uint8_t* profile_data = data;
    const uint8_t* it8_load_data = data + profile_size;
    const uint8_t* tag_write_data = data + profile_size + it8_data_size;
    
    // Variables to hold intermediate results
    cmsHPROFILE hProfile = NULL;
    cmsHANDLE hIT8 = NULL;
    cmsTagSignature tag_sig = 0;
    void* tag_data = NULL;
    cmsBool result = FALSE;
    cmsUInt32Number bytes_needed = 0;
    void* save_buffer = NULL;
    
    // Attempt to open profile from memory
    if (profile_size > 0) {
        hProfile = cmsOpenProfileFromMem(profile_data, (cmsUInt32Number)profile_size);
    }
    
    // If profile opened successfully, test reading and writing tags
    if (hProfile != NULL) {
        // Determine tag signature from input data (first 4 bytes after profile section)
        if (remaining_size >= 4) {
            // Use first 4 bytes to form a tag signature
            memcpy(&tag_sig, tag_write_data, 4);
            
            // Test reading a tag (this might fail if tag doesn't exist, which is OK)
            tag_data = cmsReadTag(hProfile, tag_sig);
            
            // Test writing a tag if there's enough data
            if (remaining_size >= 8) {
                // Use next 8 bytes as data to write to the tag
                result = cmsWriteTag(hProfile, tag_sig, tag_write_data);
            } else {
                // Try to write NULL to delete the tag (if it exists)
                result = cmsWriteTag(hProfile, tag_sig, NULL);
            }
        }
        
        // Close the profile
        cmsCloseProfile(hProfile);
    }
    
    // Test IT8 functionality with the second portion of data
    if (it8_data_size > 0) {
        hIT8 = cmsIT8LoadFromMem(NULL, it8_load_data, (cmsUInt32Number)it8_data_size);
        
        if (hIT8 != NULL) {
            // Test saving IT8 data to memory
            // First call to get required size
            cmsIT8SaveToMem(hIT8, NULL, &bytes_needed);
            
            if (bytes_needed > 0) {
                // Allocate buffer for saving
                save_buffer = malloc(bytes_needed);
                if (save_buffer) {
                    cmsIT8SaveToMem(hIT8, save_buffer, &bytes_needed);
                    free(save_buffer);
                }
            }
            
            // Free the IT8 handle
            cmsIT8Free(hIT8);
        }
    }
    
    // Clean up any remaining allocated resources
    // (Though most should be handled by the library)
    
    return 0;
}
