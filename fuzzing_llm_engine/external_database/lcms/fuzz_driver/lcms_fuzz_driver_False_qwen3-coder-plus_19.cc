#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing lcms2 API combination: cmsReadTag, cmsCloseProfile, cmsOpenProfileFromMem, cmsWriteTag, cmsSaveProfileToMem

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be meaningful
    if (size < sizeof(cmsUInt32Number) + 1) {
        return 0;
    }

    cmsHPROFILE hProfile = NULL;
    cmsHPROFILE hProfileCopy = NULL;
    void *tagData = NULL;
    cmsUInt32Number bytesNeeded = 0;
    void *profileBuffer = NULL;
    
    // Attempt to open profile from input data
    hProfile = cmsOpenProfileFromMem(data, (cmsUInt32Number)size);
    if (hProfile == NULL) {
        // If opening fails, try creating a basic profile for testing
        hProfile = cmsCreate_sRGBProfile();
        if (hProfile == NULL) {
            return 0;
        }
    }

    // Extract tag signature from input data (using first 4 bytes as tag signature)
    cmsTagSignature tagSig = 0;
    if (size >= sizeof(cmsTagSignature)) {
        memcpy(&tagSig, data, sizeof(cmsTagSignature));
        // Ensure tagSig is not zero to avoid invalid signatures
        if (tagSig == 0) {
            tagSig = cmsSigRedColorantTag; // Default to a known valid tag
        }
    } else {
        tagSig = cmsSigRedColorantTag; // Default to a known valid tag
    }

    // Try to read a tag from the profile
    tagData = cmsReadTag(hProfile, tagSig);
    // Note: We don't free tagData since it's managed internally by the profile
    
    // Try to save profile to memory to determine required size
    cmsBool result = cmsSaveProfileToMem(hProfile, NULL, &bytesNeeded);
    if (result && bytesNeeded > 0) {
        // Allocate buffer for profile data
        profileBuffer = malloc(bytesNeeded);
        if (profileBuffer) {
            cmsUInt32Number actualBytes = bytesNeeded;
            result = cmsSaveProfileToMem(hProfile, profileBuffer, &actualBytes);
            
            if (result) {
                // Open a copy of the profile from the saved memory buffer
                hProfileCopy = cmsOpenProfileFromMem(profileBuffer, actualBytes);
                
                if (hProfileCopy) {
                    // Try to read the same tag from the copied profile
                    void *copiedTagData = cmsReadTag(hProfileCopy, tagSig);
                    // Note: We don't free copiedTagData since it's managed internally
                    
                    // Try to write the tag back to the original profile (if it wasn't originally read)
                    if (tagData == NULL) {
                        // Write a dummy tag - using profile header as example data
                        cmsProfileClassSignature deviceClass = cmsGetDeviceClass(hProfile);
                        cmsWriteTag(hProfile, tagSig, &deviceClass);
                    } else {
                        // Write the read tag back to the profile
                        cmsWriteTag(hProfile, tagSig, tagData);
                    }
                    
                    // Close the copied profile
                    cmsCloseProfile(hProfileCopy);
                }
            }
        }
    }
    
    // Clean up allocated memory
    if (profileBuffer) {
        free(profileBuffer);
    }
    
    // Close the original profile
    cmsCloseProfile(hProfile);
    
    return 0;
}
