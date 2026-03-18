#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing LCMS2 APIs: cmsIT8Free, cmsCloseProfile, cmsIT8LoadFromMem, 
// cmsIT8SaveToMem, cmsFreeToneCurve, cmsGetTagCount

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables to avoid undefined behavior
    cmsHANDLE hIT8 = NULL;
    cmsHPROFILE hProfile = NULL;
    cmsToneCurve* toneCurve = NULL;
    void* saveBuffer = NULL;
    cmsUInt32Number bytesNeeded = 0;
    
    // Early exit if input is too small to be meaningful
    if (size < 10) {
        return 0;
    }
    
    // Calculate split point for different operations
    size_t it8Size = size / 2;
    if (it8Size == 0) {
        it8Size = 1;
    }
    
    // Try to load IT8 data from memory
    hIT8 = cmsIT8LoadFromMem(NULL, data, (cmsUInt32Number)it8Size);
    
    // Test cmsIT8SaveToMem - first call to get required size
    if (hIT8 != NULL) {
        cmsBool saveResult = cmsIT8SaveToMem(hIT8, NULL, &bytesNeeded);
        if (saveResult && bytesNeeded > 0) {
            // Allocate buffer for saving
            saveBuffer = malloc(bytesNeeded);
            if (saveBuffer) {
                // Actually save to the allocated buffer
                cmsIT8SaveToMem(hIT8, saveBuffer, &bytesNeeded);
            }
        }
        
        // Free the IT8 handle
        cmsIT8Free(hIT8);
        hIT8 = NULL;
    }
    
    // Create a simple tone curve for testing
    cmsFloat32Number curveValues[] = {0.0f, 0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f, 0.9f, 1.0f};
    cmsUInt32Number nPoints = sizeof(curveValues) / sizeof(curveValues[0]);
    
    // Only create tone curve if we have enough data points
    if (nPoints >= 2) {
        toneCurve = cmsBuildTabulatedToneCurveFloat(NULL, nPoints, curveValues);
        
        if (toneCurve != NULL) {
            // Test cmsFreeToneCurve
            cmsFreeToneCurve(toneCurve);
            toneCurve = NULL;
        }
    }
    
    // Create a minimal profile for testing cmsGetTagCount and cmsCloseProfile
    cmsHPROFILE profile = cmsCreate_sRGBProfile();
    if (profile != NULL) {
        // Test cmsGetTagCount
        cmsInt32Number tagCount = cmsGetTagCount(profile);
        
        // Close the profile
        cmsBool closeResult = cmsCloseProfile(profile);
        (void)closeResult; // Suppress unused variable warning
    }
    
    // Create another profile to test with potentially different data
    cmsCIExyY whitePoint;
    cmsCIExyYTRIPLE primaries;
    
    // Use input data to initialize color values if possible
    if (size >= sizeof(whitePoint) + sizeof(primaries)) {
        memcpy(&whitePoint, data, sizeof(whitePoint));
        memcpy(&primaries, data + sizeof(whitePoint), sizeof(primaries));
        
        // Normalize values to valid ranges
        whitePoint.x = fmod(whitePoint.x, 1.0f);
        whitePoint.y = fmod(whitePoint.y, 1.0f);
        whitePoint.Y = fmod(whitePoint.Y, 1.0f);
        
        primaries.Red.x = fmod(primaries.Red.x, 1.0f);
        primaries.Red.y = fmod(primaries.Red.y, 1.0f);
        primaries.Red.Y = fmod(primaries.Red.Y, 1.0f);
        
        primaries.Green.x = fmod(primaries.Green.x, 1.0f);
        primaries.Green.y = fmod(primaries.Green.y, 1.0f);
        primaries.Green.Y = fmod(primaries.Green.Y, 1.0f);
        
        primaries.Blue.x = fmod(primaries.Blue.x, 1.0f);
        primaries.Blue.y = fmod(primaries.Blue.y, 1.0f);
        primaries.Blue.Y = fmod(primaries.Blue.Y, 1.0f);
        
        cmsHPROFILE customProfile = cmsCreateRGBProfile(&whitePoint, &primaries, NULL);
        if (customProfile != NULL) {
            cmsInt32Number customTagCount = cmsGetTagCount(customProfile);
            (void)customTagCount; // Suppress unused variable warning
            
            cmsCloseProfile(customProfile);
        }
    }
    
    // Clean up allocated save buffer
    if (saveBuffer) {
        free(saveBuffer);
        saveBuffer = NULL;
    }
    
    return 0;
}
