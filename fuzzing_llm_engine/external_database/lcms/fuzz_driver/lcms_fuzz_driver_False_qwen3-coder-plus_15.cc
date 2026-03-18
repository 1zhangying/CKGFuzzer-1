#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver implementation for Little CMS (lcms2) library APIs
// Tests: cmsIT8Free, cmsCreateRGBProfile, cmsOpenProfileFromMem, 
//        cmsIT8LoadFromMem, cmsIT8SaveToMem, cmsSaveProfileToMem

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to process
    if (size < 10) {
        return 0;
    }

    // Split the input data into different segments for various operations
    size_t offset = 0;
    
    // Create RGB profile with some data from input
    if (size >= sizeof(cmsCIExyY) * 2 + sizeof(cmsToneCurve*) * 3) {
        // Extract white point data
        cmsCIExyY whitePoint;
        if (offset + sizeof(cmsCIExyY) <= size) {
            memcpy(&whitePoint, data + offset, sizeof(cmsCIExyY));
            offset += sizeof(cmsCIExyY);
        } else {
            whitePoint.x = 0.3127f; // D65 white point x
            whitePoint.y = 0.3290f; // D65 white point y
            whitePoint.Y = 1.0f;
        }

        // Extract primaries data
        cmsCIExyYTRIPLE primaries;
        if (offset + sizeof(cmsCIExyYTRIPLE) <= size) {
            memcpy(&primaries, data + offset, sizeof(cmsCIExyYTRIPLE));
            offset += sizeof(cmsCIExyYTRIPLE);
        } else {
            // Default sRGB primaries
            primaries.Red.x = 0.64f;
            primaries.Red.y = 0.33f;
            primaries.Red.Y = 1.0f;
            primaries.Green.x = 0.30f;
            primaries.Green.y = 0.60f;
            primaries.Green.Y = 1.0f;
            primaries.Blue.x = 0.15f;
            primaries.Blue.y = 0.06f;
            primaries.Blue.Y = 1.0f;
        }

        // Create tone curves for RGB channels
        cmsToneCurve* transferFunctions[3];
        
        // Use remaining data to create tone curves if possible
        if (size - offset >= 3 * sizeof(cmsFloat32Number) * 2) { // At least 2 points per curve
            for (int i = 0; i < 3; ++i) {
                cmsFloat32Number curvePoints[2] = {0.0f, 1.0f};
                if (offset + sizeof(cmsFloat32Number) * 2 <= size) {
                    memcpy(curvePoints, data + offset, sizeof(cmsFloat32Number) * 2);
                    offset += sizeof(cmsFloat32Number) * 2;
                    
                    // Ensure valid gamma value
                    if (curvePoints[1] == 0.0f) curvePoints[1] = 1.0f;
                }
                
                transferFunctions[i] = cmsBuildGamma(NULL, curvePoints[1]);
            }
        } else {
            // Create default gamma curves
            for (int i = 0; i < 3; ++i) {
                transferFunctions[i] = cmsBuildGamma(NULL, 2.2);
            }
        }

        // Create RGB profile
        cmsHPROFILE hProfile = cmsCreateRGBProfile(&whitePoint, &primaries, transferFunctions);
        
        if (hProfile != NULL) {
            // Test cmsSaveProfileToMem to save profile to memory
            cmsUInt32Number profileSize = 0;
            
            // First call to get required size
            cmsSaveProfileToMem(hProfile, NULL, &profileSize);
            
            if (profileSize > 0) {
                void* profileBuffer = malloc(profileSize);
                if (profileBuffer != NULL) {
                    if (cmsSaveProfileToMem(hProfile, profileBuffer, &profileSize)) {
                        // Try to open the saved profile from memory
                        cmsHPROFILE hLoadedProfile = cmsOpenProfileFromMem(profileBuffer, profileSize);
                        
                        if (hLoadedProfile != NULL) {
                            cmsCloseProfile(hLoadedProfile);
                        }
                    }
                    free(profileBuffer);
                }
            }
            
            // Clean up the original profile
            cmsCloseProfile(hProfile);
        }

        // Free the tone curves
        for (int i = 0; i < 3; ++i) {
            if (transferFunctions[i] != NULL) {
                cmsFreeToneCurve(transferFunctions[i]);
            }
        }
    }

    // Test cmsIT8LoadFromMem and related functions
    if (size > offset && size - offset > 10) {
        size_t it8DataSize = size - offset;
        if (it8DataSize > 1024) it8DataSize = 1024; // Limit size to prevent excessive memory usage
        
        cmsHANDLE hIT8 = cmsIT8LoadFromMem(NULL, data + offset, (cmsUInt32Number)it8DataSize);
        
        if (hIT8 != NULL) {
            // Test cmsIT8SaveToMem to save IT8 data to memory
            cmsUInt32Number it8Size = 0;
            
            // First call to get required size
            cmsIT8SaveToMem(hIT8, NULL, &it8Size);
            
            if (it8Size > 0) {
                void* it8Buffer = malloc(it8Size);
                if (it8Buffer != NULL) {
                    cmsIT8SaveToMem(hIT8, it8Buffer, &it8Size);
                    free(it8Buffer);
                }
            }
            
            // Free the IT8 handle
            cmsIT8Free(hIT8);
        }
    }

    // Additional test: try opening profile from the beginning of input data
    if (size > 100) { // Need reasonable amount of data for a valid profile
        cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, (cmsUInt32Number)size);
        
        if (hProfile != NULL) {
            // Save it back to memory
            cmsUInt32Number profileSize = 0;
            cmsSaveProfileToMem(hProfile, NULL, &profileSize);
            
            if (profileSize > 0) {
                void* profileBuffer = malloc(profileSize);
                if (profileBuffer != NULL) {
                    cmsSaveProfileToMem(hProfile, profileBuffer, &profileSize);
                    free(profileBuffer);
                }
            }
            
            cmsCloseProfile(hProfile);
        }
    }

    return 0;
}
