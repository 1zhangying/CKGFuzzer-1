#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for lcms2 library testing
// Tests the following APIs: cmsReadTag, cmsCloseProfile, cmsOpenProfileFromMem, cmsWriteTag, cmsSaveProfileToMem

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsTagSignature) + 1) {
        return 0; // Need at least enough data for a tag signature and some content
    }

    cmsHPROFILE hProfile = NULL;
    cmsHPROFILE hNewProfile = NULL;
    void* tagData = NULL;
    cmsUInt32Number bytesNeeded = 0;
    uint8_t* profileBuffer = NULL;
    
    // Extract tag signature from input data (first 4 bytes)
    cmsTagSignature tagSig = *((cmsTagSignature*)data);
    const uint8_t* profileData = data + sizeof(cmsTagSignature);
    size_t profileSize = size - sizeof(cmsTagSignature);
    
    // Limit profile size to prevent excessive memory allocation
    if (profileSize > 10 * 1024 * 1024) { // 10MB limit
        profileSize = 10 * 1024 * 1024;
    }
    
    // Try to open profile from memory
    if (profileSize > 0) {
        hProfile = cmsOpenProfileFromMem(profileData, (cmsUInt32Number)profileSize);
    }
    
    if (hProfile != NULL) {
        // Test reading a tag from the profile
        tagData = cmsReadTag(hProfile, tagSig);
        
        // Test writing a tag to the profile (if there's additional data)
        if (size > sizeof(cmsTagSignature) + sizeof(cmsTagSignature)) {
            const uint8_t* writeTagData = data + sizeof(cmsTagSignature) * 2;
            size_t writeTagSize = size - sizeof(cmsTagSignature) * 2;
            
            // For this test, we'll try to write a simple value based on available data
            // Note: We can't write arbitrary data as the library expects specific tag structures
            // So we'll attempt to write only if we have a valid tag signature in our data
            if (writeTagSize >= sizeof(cmsTagSignature)) {
                cmsTagSignature writeTagSig = *((cmsTagSignature*)(data + sizeof(cmsTagSignature)));
                
                // We can't write arbitrary data without knowing the tag structure,
                // so we'll just try to delete a tag instead (passing NULL as data)
                cmsWriteTag(hProfile, writeTagSig, NULL);
            }
        }
        
        // Test saving profile to memory
        if (cmsSaveProfileToMem(hProfile, NULL, &bytesNeeded)) {
            if (bytesNeeded > 0 && bytesNeeded <= 10 * 1024 * 1024) { // Safety check
                profileBuffer = (uint8_t*)malloc(bytesNeeded);
                if (profileBuffer != NULL) {
                    if (cmsSaveProfileToMem(hProfile, profileBuffer, &bytesNeeded)) {
                        // Try opening the saved profile as well
                        hNewProfile = cmsOpenProfileFromMem(profileBuffer, bytesNeeded);
                        if (hNewProfile) {
                            cmsCloseProfile(hNewProfile);
                        }
                    }
                    free(profileBuffer);
                    profileBuffer = NULL;
                }
            }
        }
        
        // Close the original profile
        cmsCloseProfile(hProfile);
    }
    
    // Cleanup
    if (profileBuffer != NULL) {
        free(profileBuffer);
    }
    
    return 0;
}
