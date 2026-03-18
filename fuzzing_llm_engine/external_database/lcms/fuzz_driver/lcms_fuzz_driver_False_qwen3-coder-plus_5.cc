#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for Little CMS (lcms2) library
// Tests the following APIs: cmsReadTag, cmsOpenProfileFromMem, cmsCreateTransform, cmsDoTransform, cmsCreateProofingTransform
// Uses input data to create color profiles and perform color space transformations

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if there's not enough data for basic operations
    if (size < sizeof(cmsUInt32Number) * 4) {
        return 0;
    }

    cmsHPROFILE hInputProfile = NULL;
    cmsHPROFILE hOutputProfile = NULL;
    cmsHPROFILE hProofProfile = NULL;
    cmsHTRANSFORM hTransform = NULL;
    cmsHTRANSFORM hProofTransform = NULL;
    
    // Extract parameters from input data
    // Using first few bytes to determine format and intent parameters
    cmsUInt32Number inputFormat = 0;
    cmsUInt32Number outputFormat = 0;
    cmsUInt32Number proofFormat = 0;
    cmsUInt32Number intent = 0;
    cmsUInt32Number proofIntent = 0;
    cmsUInt32Number flags = 0;
    
    // Extract parameters from input data if possible
    if (size >= sizeof(cmsUInt32Number) * 6) {
        memcpy(&inputFormat, data, sizeof(cmsUInt32Number));
        memcpy(&outputFormat, data + sizeof(cmsUInt32Number), sizeof(cmsUInt32Number));
        memcpy(&proofFormat, data + 2 * sizeof(cmsUInt32Number), sizeof(cmsUInt32Number));
        memcpy(&intent, data + 3 * sizeof(cmsUInt32Number), sizeof(cmsUInt32Number));
        memcpy(&proofIntent, data + 4 * sizeof(cmsUInt32Number), sizeof(cmsUInt32Number));
        memcpy(&flags, data + 5 * sizeof(cmsUInt32Number), sizeof(cmsUInt32Number));
        
        // Bound the extracted values to valid ranges
        inputFormat %= 0x10000;  // Limit to reasonable range
        outputFormat %= 0x10000;
        proofFormat %= 0x10000;
        intent %= 4;  // Valid intents are typically 0-3
        proofIntent %= 4;
        flags %= 0x10000;
    } else {
        // Default values if not enough data
        inputFormat = TYPE_RGB_8;
        outputFormat = TYPE_RGB_8;
        proofFormat = TYPE_RGB_8;
        intent = INTENT_PERCEPTUAL;
        proofIntent = INTENT_PERCEPTUAL;
        flags = 0;
    }

    // Advance data pointer past parameter extraction
    size_t consumed = sizeof(cmsUInt32Number) * 6;
    if (size <= consumed) {
        return 0;
    }
    
    const uint8_t* profileData = data + consumed;
    size_t profileSize = size - consumed;
    
    // Skip if not enough data for a valid profile
    if (profileSize < 100) {  // ICC profiles have minimum size requirements
        return 0;
    }

    // Try to open input profile from memory
    hInputProfile = cmsOpenProfileFromMem(profileData, (cmsUInt32Number)profileSize);
    if (hInputProfile == NULL) {
        // If we can't open the first profile, try a default sRGB profile instead
        hInputProfile = cmsCreate_sRGBProfile();
        if (hInputProfile == NULL) {
            return 0;
        }
    }

    // Try to open output profile from memory (using different slice of data)
    size_t outputOffset = profileSize / 2;
    if (outputOffset > 0 && profileSize > outputOffset) {
        hOutputProfile = cmsOpenProfileFromMem(profileData + outputOffset, 
                                              (cmsUInt32Number)(profileSize - outputOffset));
    }
    
    if (hOutputProfile == NULL) {
        // Fallback to a standard profile if the custom one fails
        hOutputProfile = cmsCreate_sRGBProfile();
    }

    // Try to open proofing profile from memory (using another slice)
    size_t proofOffset = profileSize / 4;
    if (proofOffset > 0 && profileSize > proofOffset) {
        hProofProfile = cmsOpenProfileFromMem(profileData + proofOffset, 
                                             (cmsUInt32Number)(profileSize - proofOffset));
    }
    
    if (hProofProfile == NULL) {
        // Fallback to a standard profile
        hProofProfile = cmsCreate_sRGBProfile();
    }

    // Test cmsReadTag functionality
    if (hInputProfile != NULL) {
        // Try to read some common tags
        cmsTagSignature tags[] = { 
            cmsSigRedColorantTag, 
            cmsSigGreenColorantTag, 
            cmsSigBlueColorantTag, 
            cmsSigMediaWhitePointTag,
            cmsSigDeviceModelDescTag,
            cmsSigProfileDescriptionTag
        };
        
        for (int i = 0; i < 6; i++) {
            void* tagData = cmsReadTag(hInputProfile, tags[i]);
            // Note: Don't free the returned tag data as it's owned by the profile
            (void)tagData; // Suppress unused variable warning
        }
    }

    // Test cmsCreateTransform
    if (hInputProfile != NULL && hOutputProfile != NULL) {
        hTransform = cmsCreateTransform(
            hInputProfile,
            inputFormat,
            hOutputProfile,
            outputFormat,
            intent,
            flags
        );
    }

    // Test cmsCreateProofingTransform
    if (hInputProfile != NULL && hOutputProfile != NULL && hProofProfile != NULL) {
        hProofTransform = cmsCreateProofingTransform(
            hInputProfile,
            inputFormat,
            hOutputProfile,
            outputFormat,
            hProofProfile,
            intent,
            proofIntent,
            flags
        );
    }

    // Test cmsDoTransform if we have a valid transform
    if (hTransform != NULL) {
        // Create dummy input and output buffers
        const int pixelCount = 100;  // Use a fixed small number to avoid memory issues
        cmsUInt8Number* inputBuffer = (cmsUInt8Number*)malloc(pixelCount * 3); // RGB
        cmsUInt8Number* outputBuffer = (cmsUInt8Number*)malloc(pixelCount * 3); // RGB
        
        if (inputBuffer != NULL && outputBuffer != NULL) {
            // Initialize input with some data from fuzzer input
            size_t srcSize = size - consumed;
            for (int i = 0; i < pixelCount * 3 && i < srcSize; i++) {
                inputBuffer[i] = data[consumed + i];
            }
            
            // Perform the transformation
            cmsDoTransform(hTransform, inputBuffer, outputBuffer, pixelCount);
        }
        
        // Clean up buffers
        free(inputBuffer);
        free(outputBuffer);
    }

    // Test cmsDoTransform with proofing transform
    if (hProofTransform != NULL) {
        const int pixelCount = 100;  // Use a fixed small number to avoid memory issues
        cmsUInt8Number* inputBuffer = (cmsUInt8Number*)malloc(pixelCount * 3); // RGB
        cmsUInt8Number* outputBuffer = (cmsUInt8Number*)malloc(pixelCount * 3); // RGB
        
        if (inputBuffer != NULL && outputBuffer != NULL) {
            // Initialize input with some data from fuzzer input
            size_t srcSize = size - consumed;
            for (int i = 0; i < pixelCount * 3 && i < srcSize; i++) {
                inputBuffer[i] = data[consumed + i];
            }
            
            // Perform the proofing transformation
            cmsDoTransform(hProofTransform, inputBuffer, outputBuffer, pixelCount);
        }
        
        // Clean up buffers
        free(inputBuffer);
        free(outputBuffer);
    }

    // Clean up resources
    if (hTransform != NULL) {
        cmsDeleteTransform(hTransform);
    }
    
    if (hProofTransform != NULL) {
        cmsDeleteTransform(hProofTransform);
    }

    // Close profiles if they were created from memory
    if (hInputProfile != NULL && size >= 100) {  // Only close if opened from memory
        cmsCloseProfile(hInputProfile);
    } else if (hInputProfile != NULL) {  // If it was a created profile
        cmsCloseProfile(hInputProfile);
    }

    if (hOutputProfile != NULL && profileSize > 100) {  // Only close if opened from memory
        cmsCloseProfile(hOutputProfile);
    } else if (hOutputProfile != NULL) {  // If it was a created profile
        cmsCloseProfile(hOutputProfile);
    }

    if (hProofProfile != NULL && profileSize > 100) {  // Only close if opened from memory
        cmsCloseProfile(hProofProfile);
    } else if (hProofProfile != NULL) {  // If it was a created profile
        cmsCloseProfile(hProofProfile);
    }

    return 0;
}
