#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 20) {
        // Need minimum data size for basic operations
        return 0;
    }

    // Extract various parameters from input data
    cmsUInt32Number profileSize = *((cmsUInt32Number*)(data));
    if (profileSize > size - 4) {
        profileSize = size - 4;
    }
    
    if (profileSize == 0) {
        return 0;
    }

    // Open profile from memory
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data + 4, profileSize);
    if (!hProfile) {
        return 0; // Invalid profile data, continue fuzzing
    }

    // Extract additional parameters for transforms
    cmsUInt32Number inputFormat = *((cmsUInt32Number*)(data + 4 + profileSize));
    cmsUInt32Number outputFormat = *((cmsUInt32Number*)(data + 8 + profileSize));
    cmsUInt32Number intent = *((cmsUInt32Number*)(data + 12 + profileSize)) % 4; // Limit to valid intent range
    cmsUInt32Number flags = *((cmsUInt32Number*)(data + 16 + profileSize));

    // Create a simple transform using the opened profile as both input and output
    cmsHTRANSFORM hTransform1 = cmsCreateTransform(
        hProfile,
        inputFormat,
        hProfile,
        outputFormat,
        intent,
        flags
    );

    if (hTransform1) {
        // Prepare dummy input/output buffers for transformation
        cmsUInt32Number bufferSize = 1024; // Fixed buffer size for testing
        cmsUInt8Number* inputBuffer = (cmsUInt8Number*)malloc(bufferSize);
        cmsUInt8Number* outputBuffer = (cmsUInt8Number*)malloc(bufferSize);

        if (inputBuffer && outputBuffer) {
            // Initialize buffers with some data from fuzz input
            size_t remainingData = size - (20 + profileSize);
            size_t copySize = (remainingData < bufferSize) ? remainingData : bufferSize;
            
            if (copySize > 0) {
                memcpy(inputBuffer, data + 20 + profileSize, copySize);
            } else {
                memset(inputBuffer, 0, bufferSize);
            }
            memset(outputBuffer, 0, bufferSize);

            // Perform the transformation
            cmsDoTransform(hTransform1, inputBuffer, outputBuffer, bufferSize / 4); // Assuming 4 bytes per pixel

            free(inputBuffer);
            free(outputBuffer);
        }

        // Clean up transform
        cmsDeleteTransform(hTransform1);
    }

    // Test multiprofile transform - we'll duplicate the same profile
    cmsHPROFILE profiles[2];
    profiles[0] = hProfile;
    profiles[1] = hProfile;

    cmsHTRANSFORM hMultiTransform = cmsCreateMultiprofileTransform(
        profiles,
        2, // Number of profiles
        inputFormat,
        outputFormat,
        intent,
        flags
    );

    if (hMultiTransform) {
        // Test the multiprofile transform with same buffers
        cmsUInt32Number bufferSize = 512;
        cmsUInt8Number* inputBuffer = (cmsUInt8Number*)malloc(bufferSize);
        cmsUInt8Number* outputBuffer = (cmsUInt8Number*)malloc(bufferSize);

        if (inputBuffer && outputBuffer) {
            size_t remainingData = size - (20 + profileSize);
            size_t copySize = (remainingData < bufferSize) ? remainingData : bufferSize;
            
            if (copySize > 0) {
                memcpy(inputBuffer, data + 20 + profileSize, copySize);
            } else {
                memset(inputBuffer, 0, bufferSize);
            }
            memset(outputBuffer, 0, bufferSize);

            cmsDoTransform(hMultiTransform, inputBuffer, outputBuffer, bufferSize / 4);

            free(inputBuffer);
            free(outputBuffer);
        }

        cmsDeleteTransform(hMultiTransform);
    }

    // Test proofing transform
    cmsHTRANSFORM hProofTransform = cmsCreateProofingTransform(
        hProfile,
        inputFormat,
        hProfile,
        outputFormat,
        hProfile, // Proofing profile (using same profile)
        intent,
        intent, // Proofing intent (same as main intent)
        flags
    );

    if (hProofTransform) {
        // Test the proofing transform
        cmsUInt32Number bufferSize = 256;
        cmsUInt8Number* inputBuffer = (cmsUInt8Number*)malloc(bufferSize);
        cmsUInt8Number* outputBuffer = (cmsUInt8Number*)malloc(bufferSize);

        if (inputBuffer && outputBuffer) {
            size_t remainingData = size - (20 + profileSize);
            size_t copySize = (remainingData < bufferSize) ? remainingData : bufferSize;
            
            if (copySize > 0) {
                memcpy(inputBuffer, data + 20 + profileSize, copySize);
            } else {
                memset(inputBuffer, 0, bufferSize);
            }
            memset(outputBuffer, 0, bufferSize);

            cmsDoTransform(hProofTransform, inputBuffer, outputBuffer, bufferSize / 4);

            free(inputBuffer);
            free(outputBuffer);
        }

        cmsDeleteTransform(hProofTransform);
    }

    // Clean up the original profile
    cmsCloseProfile(hProfile);

    return 0;
}
