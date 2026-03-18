#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for lcms2 library testing
// This fuzzer tests various color management APIs including profile handling, transforms, and tag reading
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if data is too small to be meaningful
    if (size < 16) {
        return 0;
    }

    cmsHPROFILE hProfile = NULL;
    cmsHPROFILE hProfile2 = NULL;
    cmsHPROFILE hProfile3 = NULL;
    cmsHTRANSFORM hTransform = NULL;
    cmsHTRANSFORM hMultiTransform = NULL;
    cmsHTRANSFORM hProofTransform = NULL;
    
    // Extract profile data - minimum size needed for a valid profile
    if (size < 128) {
        return 0;
    }
    
    // Try to open profile from memory
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile != NULL) {
        // Test cmsReadTag with various common tag signatures
        cmsReadTag(hProfile, cmsSigAToB0Tag);
        cmsReadTag(hProfile, cmsSigAToB1Tag);
        cmsReadTag(hProfile, cmsSigAToB2Tag);
        cmsReadTag(hProfile, cmsSigBToA0Tag);
        cmsReadTag(hProfile, cmsSigBToA1Tag);
        cmsReadTag(hProfile, cmsSigBToA2Tag);
        cmsReadTag(hProfile, cmsSigRedColorantTag);
        cmsReadTag(hProfile, cmsSigGreenColorantTag);
        cmsReadTag(hProfile, cmsSigBlueColorantTag);
        cmsReadTag(hProfile, cmsSigMediaWhitePointTag);
        
        // Create a second profile if possible - using a portion of the data
        if (size > 256) {
            hProfile2 = cmsOpenProfileFromMem(data + 128, size - 128);
        }
        
        // Create a third profile if possible
        if (hProfile2 && size > 384) {
            hProfile3 = cmsOpenProfileFromMem(data + 256, size - 256);
        }
        
        // Test cmsCreateTransform if we have a second profile
        if (hProfile2) {
            hTransform = cmsCreateTransform(
                hProfile, 
                TYPE_RGBA_8, 
                hProfile2, 
                TYPE_RGBA_8, 
                INTENT_PERCEPTUAL, 
                0
            );
            
            // Test cmsCreateProofingTransform if we have a third profile
            if (hProfile3) {
                hProofTransform = cmsCreateProofingTransform(
                    hProfile,
                    TYPE_RGBA_8,
                    hProfile2,
                    TYPE_RGBA_8,
                    hProfile3,
                    INTENT_PERCEPTUAL,
                    INTENT_RELATIVE_COLORIMETRIC,
                    0
                );
            }
            
            // Test cmsCreateMultiprofileTransform
            cmsHPROFILE profiles[3];
            int numProfiles = 0;
            
            profiles[numProfiles++] = hProfile;
            profiles[numProfiles++] = hProfile2;
            if (hProfile3) {
                profiles[numProfiles++] = hProfile3;
            }
            
            hMultiTransform = cmsCreateMultiprofileTransform(
                profiles,
                numProfiles,
                TYPE_RGBA_8,
                TYPE_RGBA_8,
                INTENT_PERCEPTUAL,
                0
            );
            
            // Test cmsDoTransform if we have a transform
            if (hTransform) {
                // Prepare input/output buffers
                unsigned char inputBuffer[1024];
                unsigned char outputBuffer[1024];
                
                // Initialize with sample data from fuzz input
                size_t bufferSize = sizeof(inputBuffer);
                for (size_t i = 0; i < bufferSize && i < size; i++) {
                    inputBuffer[i] = data[i % size];
                }
                
                // Perform the transform
                cmsDoTransform(hTransform, inputBuffer, outputBuffer, bufferSize / 4);
            }
            
            // Test proofing transform if created
            if (hProofTransform) {
                unsigned char inputBuffer[1024];
                unsigned char outputBuffer[1024];
                
                size_t bufferSize = sizeof(inputBuffer);
                for (size_t i = 0; i < bufferSize && i < size; i++) {
                    inputBuffer[i] = data[i % size];
                }
                
                cmsDoTransform(hProofTransform, inputBuffer, outputBuffer, bufferSize / 4);
            }
            
            // Test multi-profile transform if created
            if (hMultiTransform) {
                unsigned char inputBuffer[1024];
                unsigned char outputBuffer[1024];
                
                size_t bufferSize = sizeof(inputBuffer);
                for (size_t i = 0; i < bufferSize && i < size; i++) {
                    inputBuffer[i] = data[i % size];
                }
                
                cmsDoTransform(hMultiTransform, inputBuffer, outputBuffer, bufferSize / 4);
            }
            
            // Clean up transforms
            if (hTransform) {
                cmsDeleteTransform(hTransform);
            }
            
            if (hProofTransform) {
                cmsDeleteTransform(hProofTransform);
            }
            
            if (hMultiTransform) {
                cmsDeleteTransform(hMultiTransform);
            }
        }
        
        // Clean up profiles
        if (hProfile2) {
            cmsCloseProfile(hProfile2);
        }
        
        if (hProfile3) {
            cmsCloseProfile(hProfile3);
        }
    }
    
    // Clean up main profile
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }
    
    return 0;
}
