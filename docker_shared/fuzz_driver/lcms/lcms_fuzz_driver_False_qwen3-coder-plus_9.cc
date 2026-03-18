#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for LCMS2 color management APIs
// This fuzzer tests various transform creation and manipulation functions
// along with IT8 handle management.

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if data is too small to process
    if (size < 32) {
        return 0;
    }

    // Variables to hold extracted parameters from fuzz input
    cmsUInt32Number inputFormat = 0;
    cmsUInt32Number outputFormat = 0;
    cmsUInt32Number intent = 0;
    cmsUInt32Number flags = 0;
    cmsUInt32Number proofingIntent = 0;
    cmsUInt32Number nProfiles = 0;

    // Extract parameters from input data safely
    if (size >= sizeof(cmsUInt32Number) * 6) {
        inputFormat = *((cmsUInt32Number*)(data));
        outputFormat = *((cmsUInt32Number*)(data + sizeof(cmsUInt32Number)));
        intent = *((cmsUInt32Number*)(data + sizeof(cmsUInt32Number) * 2));
        flags = *((cmsUInt32Number*)(data + sizeof(cmsUInt32Number) * 3));
        proofingIntent = *((cmsUInt32Number*)(data + sizeof(cmsUInt32Number) * 4));
        nProfiles = *((cmsUInt32Number*)(data + sizeof(cmsUInt32Number) * 5));
        
        // Normalize nProfiles to valid range [1, 10] to avoid excessive allocations
        nProfiles = (nProfiles % 10) + 1;
    } else {
        // Use default values if not enough data
        inputFormat = TYPE_RGB_8;
        outputFormat = TYPE_CMYK_8;
        intent = INTENT_PERCEPTUAL;
        flags = 0;
        proofingIntent = INTENT_RELATIVE_COLORIMETRIC;
        nProfiles = 1;
    }

    // Clamp intent and proofingIntent to valid ranges
    intent = intent % 4;  // Valid intents are 0-3
    proofingIntent = proofingIntent % 4;

    // Create dummy profiles for testing - these are simplified for fuzzing
    cmsHPROFILE hInputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE hOutputProfile = cmsCreateLab4Profile(NULL);
    cmsHPROFILE hProofProfile = cmsCreateXYZProfile();

    // Arrays to hold profile handles for multiprofile transform
    cmsHPROFILE* hProfiles = NULL;
    cmsHTRANSFORM hTransform = NULL;
    cmsHTRANSFORM hMultiTransform = NULL;
    cmsHTRANSFORM hProofTransform = NULL;
    cmsHANDLE hIT8 = NULL;

    // Allocate and initialize profiles array
    hProfiles = (cmsHPROFILE*)malloc(nProfiles * sizeof(cmsHPROFILE));
    if (!hProfiles) {
        goto cleanup;
    }

    // Fill profiles array with copies of input profile
    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        hProfiles[i] = hInputProfile;  // Using same profile for simplicity
    }

    // Test cmsCreateTransform
    hTransform = cmsCreateTransform(hInputProfile, inputFormat, hOutputProfile, outputFormat, intent, flags);
    
    // Test cmsCreateMultiprofileTransform
    hMultiTransform = cmsCreateMultiprofileTransform(hProfiles, nProfiles, inputFormat, outputFormat, intent, flags);
    
    // Test cmsCreateProofingTransform
    hProofTransform = cmsCreateProofingTransform(hInputProfile, inputFormat, hOutputProfile, outputFormat, 
                                                hProofProfile, intent, proofingIntent, flags);

    // Prepare buffers for cmsDoTransform
    cmsUInt32Number pixelCount = 10;  // Fixed size for fuzzing
    cmsUInt32Number inputBufferSize = pixelCount * cmsBytesPerPixel(inputFormat);
    cmsUInt32Number outputBufferSize = pixelCount * cmsBytesPerPixel(outputFormat);
    
    // Ensure we have enough data for the buffers
    if (size >= inputBufferSize + 8) {  // Adding offset to access data beyond initial parameters
        unsigned char* inputBuffer = (unsigned char*)malloc(inputBufferSize);
        unsigned char* outputBuffer = (unsigned char*)malloc(outputBufferSize);
        
        if (inputBuffer && outputBuffer) {
            // Copy input data to input buffer
            memcpy(inputBuffer, data + 8, (inputBufferSize < size - 8) ? inputBufferSize : size - 8);
            
            // Initialize output buffer to zero
            memset(outputBuffer, 0, outputBufferSize);
            
            // Test cmsDoTransform with each transform
            if (hTransform) {
                cmsDoTransform(hTransform, inputBuffer, outputBuffer, pixelCount);
            }
            
            if (hMultiTransform) {
                cmsDoTransform(hMultiTransform, inputBuffer, outputBuffer, pixelCount);
            }
            
            if (hProofTransform) {
                cmsDoTransform(hProofTransform, inputBuffer, outputBuffer, pixelCount);
            }
            
            free(inputBuffer);
            free(outputBuffer);
        }
    }

    // Test cmsIT8Free - creating dummy IT8 handle for testing
    // In real usage this would come from cmsIT8Load... functions
    // For fuzzing purposes, we'll just call cmsIT8Free with NULL which is valid
    cmsIT8Free(hIT8);  // Passing NULL is valid and will just return

cleanup:
    // Clean up transforms
    if (hTransform) {
        cmsDeleteTransform(hTransform);
    }
    
    if (hMultiTransform) {
        cmsDeleteTransform(hMultiTransform);
    }
    
    if (hProofTransform) {
        cmsDeleteTransform(hProofTransform);
    }
    
    // Free profile handles
    if (hInputProfile) {
        cmsCloseProfile(hInputProfile);
    }
    
    if (hOutputProfile) {
        cmsCloseProfile(hOutputProfile);
    }
    
    if (hProofProfile) {
        cmsCloseProfile(hProofProfile);
    }
    
    // Free profiles array
    if (hProfiles) {
        free(hProfiles);
    }

    return 0;
}
