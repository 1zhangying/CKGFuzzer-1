#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing lcms2 APIs: cmsReadTag, cmsCloseProfile, cmsOpenProfileFromFile,
// cmsOpenProfileFromMem, cmsSaveProfileToMem

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if data is too small to be useful
    if (size < 16) {
        return 0;
    }

    // Extract a portion of the input data to use as a tag signature
    // A tag signature in ICC profiles is typically 4 bytes
    if (size < sizeof(cmsTagSignature)) {
        return 0;
    }
    
    cmsTagSignature tagSig = *(cmsTagSignature*)data;
    
    // Calculate remaining data for profile creation
    const uint8_t* profileData = data + sizeof(cmsTagSignature);
    size_t profileSize = size - sizeof(cmsTagSignature);
    
    cmsHPROFILE hProfile = NULL;
    cmsHPROFILE hProfileFromFile = NULL;
    void* tagData = NULL;
    void* savedProfileBuffer = NULL;
    cmsUInt32Number bytesNeeded = 0;
    FILE* tempFile = NULL;
    char tempFileName[] = "temp_profile.icc";

    // Attempt to open profile from memory
    if (profileSize > 0) {
        hProfile = cmsOpenProfileFromMem(profileData, (cmsUInt32Number)profileSize);
    }

    // If profile opened successfully from memory, try to read a tag
    if (hProfile != NULL) {
        tagData = cmsReadTag(hProfile, tagSig);
        // Note: cmsReadTag returns internal data, do not free it
        
        // Try to save profile to memory to get required size
        if (cmsSaveProfileToMem(hProfile, NULL, &bytesNeeded)) {
            if (bytesNeeded > 0) {
                savedProfileBuffer = malloc(bytesNeeded);
                if (savedProfileBuffer != NULL) {
                    // Actually save the profile to the allocated buffer
                    if (!cmsSaveProfileToMem(hProfile, savedProfileBuffer, &bytesNeeded)) {
                        free(savedProfileBuffer);
                        savedProfileBuffer = NULL;
                    }
                }
            }
        }
    }

    // Create a temporary file with the input data to test cmsOpenProfileFromFile
    tempFile = fopen(tempFileName, "wb");
    if (tempFile != NULL && size > 0) {
        fwrite(data, 1, size, tempFile);
        fclose(tempFile);
        
        // Open profile from the created file
        hProfileFromFile = cmsOpenProfileFromFile(tempFileName, "r");
        
        if (hProfileFromFile != NULL) {
            // Try to read a tag from the file-based profile
            void* fileTagData = cmsReadTag(hProfileFromFile, tagSig);
            // Do not free fileTagData as it points to internal data
            
            // Close the file-based profile
            cmsCloseProfile(hProfileFromFile);
        }
    }

    // Clean up resources
    if (savedProfileBuffer != NULL) {
        free(savedProfileBuffer);
    }

    // Close the memory-based profile if it was opened
    if (hProfile != NULL) {
        cmsCloseProfile(hProfile);
    }

    // Remove temporary file if it exists
    remove(tempFileName);

    return 0;
}
