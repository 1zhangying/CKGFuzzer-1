#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for LCMS2 color management library
// This fuzzer tests various profile creation and transformation APIs
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if we don't have enough data
    if (size < sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE) + 3 * sizeof(cmsToneCurve*)) {
        return 0;
    }

    cmsHPROFILE labProfile = nullptr;
    cmsHPROFILE rgbProfile = nullptr;
    cmsHPROFILE srgbProfile = nullptr;
    cmsHPROFILE grayProfile = nullptr;
    cmsHTRANSFORM transform = nullptr;
    
    // Allocate and initialize tone curves for RGB profile
    cmsToneCurve* toneCurves[3] = {nullptr, nullptr, nullptr};
    
    // Create a simple tone curve for testing
    cmsFloat64Number gammaParams[] = {2.2, 1.0}; // Gamma 2.2 curve
    toneCurves[0] = cmsBuildParametricToneCurve(NULL, 1, gammaParams);
    toneCurves[1] = cmsBuildParametricToneCurve(NULL, 1, gammaParams);
    toneCurves[2] = cmsBuildParametricToneCurve(NULL, 1, gammaParams);
    
    // Calculate available data offset after initial allocations
    size_t offset = 0;
    
    // Create Lab profile with D50 white point (default)
    labProfile = cmsCreateLab4Profile(nullptr);  // Uses default D50 white point
    
    // Try to create RGB profile if we have enough data
    if (size >= offset + sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE)) {
        cmsCIExyY whitePoint;
        cmsCIExyYTRIPLE primaries;
        
        // Copy white point data from fuzz input
        size_t whitePointSize = sizeof(cmsCIExyY);
        if (offset + whitePointSize <= size) {
            memcpy(&whitePoint, data + offset, whitePointSize);
            offset += whitePointSize;
            
            // Copy primaries data from fuzz input
            size_t primariesSize = sizeof(cmsCIExyYTRIPLE);
            if (offset + primariesSize <= size) {
                memcpy(&primaries, data + offset, primariesSize);
                offset += primariesSize;
                
                // Create RGB profile
                rgbProfile = cmsCreateRGBProfile(&whitePoint, &primaries, toneCurves);
            }
        }
    }
    
    // Create sRGB profile (no input data required)
    srgbProfile = cmsCreate_sRGBProfile();
    
    // Create gray profile if we have enough data
    cmsToneCurve* grayToneCurve = nullptr;
    if (size > offset + sizeof(cmsCIExyY)) {
        cmsCIExyY grayWhitePoint;
        size_t whitePointSize = sizeof(cmsCIExyY);
        memcpy(&grayWhitePoint, data + offset, whitePointSize);
        offset += whitePointSize;
        
        // Create a simple tone curve for gray
        grayToneCurve = cmsBuildParametricToneCurve(NULL, 1, gammaParams);
        if (grayToneCurve) {
            grayProfile = cmsCreateGrayProfile(&grayWhitePoint, grayToneCurve);
        }
    }
    
    // Create various transforms based on available profiles
    if (labProfile && srgbProfile) {
        // Create transform from Lab to sRGB
        transform = cmsCreateTransform(
            labProfile, 
            TYPE_Lab_DBL, 
            srgbProfile, 
            TYPE_RGB_8, 
            INTENT_PERCEPTUAL, 
            0
        );
        
        if (transform) {
            // Clean up transform
            cmsDeleteTransform(transform);
            transform = nullptr;
        }
    }
    
    if (rgbProfile && labProfile) {
        // Create transform from RGB to Lab
        transform = cmsCreateTransform(
            rgbProfile, 
            TYPE_RGB_8, 
            labProfile, 
            TYPE_Lab_DBL, 
            INTENT_RELATIVE_COLORIMETRIC, 
            0
        );
        
        if (transform) {
            // Clean up transform
            cmsDeleteTransform(transform);
            transform = nullptr;
        }
    }
    
    if (srgbProfile && grayProfile) {
        // Create transform from sRGB to Gray
        transform = cmsCreateTransform(
            srgbProfile, 
            TYPE_RGB_8, 
            grayProfile, 
            TYPE_GRAY_8, 
            INTENT_SATURATION, 
            0
        );
        
        if (transform) {
            // Clean up transform
            cmsDeleteTransform(transform);
            transform = nullptr;
        }
    }
    
    // Test with different intents based on input data
    if (rgbProfile && srgbProfile && size > offset) {
        int intent = data[offset] % 4; // Choose intent based on input data
        cmsUInt32Number cmsIntent;
        
        switch(intent) {
            case 0: cmsIntent = INTENT_PERCEPTUAL; break;
            case 1: cmsIntent = INTENT_RELATIVE_COLORIMETRIC; break;
            case 2: cmsIntent = INTENT_SATURATION; break;
            case 3: cmsIntent = INTENT_ABSOLUTE_COLORIMETRIC; break;
            default: cmsIntent = INTENT_PERCEPTUAL; break;
        }
        
        transform = cmsCreateTransform(
            rgbProfile, 
            TYPE_RGB_8, 
            srgbProfile, 
            TYPE_RGB_8, 
            cmsIntent, 
            0
        );
        
        if (transform) {
            // Clean up transform
            cmsDeleteTransform(transform);
            transform = nullptr;
        }
    }
    
    // Free all allocated resources
    if (labProfile) {
        cmsCloseProfile(labProfile);
    }
    
    if (rgbProfile) {
        cmsCloseProfile(rgbProfile);
    }
    
    if (srgbProfile) {
        cmsCloseProfile(srgbProfile);
    }
    
    if (grayProfile) {
        cmsCloseProfile(grayProfile);
    }
    
    // Free tone curves
    if (toneCurves[0]) {
        cmsFreeToneCurve(toneCurves[0]);
    }
    if (toneCurves[1]) {
        cmsFreeToneCurve(toneCurves[1]);
    }
    if (toneCurves[2]) {
        cmsFreeToneCurve(toneCurves[2]);
    }
    
    if (grayToneCurve) {
        cmsFreeToneCurve(grayToneCurve);
    }
    
    return 0;
}
