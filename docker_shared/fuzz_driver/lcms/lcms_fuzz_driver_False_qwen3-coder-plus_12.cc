#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing lcms2 APIs: cmsReadTag, cmsCloseProfile, cmsOpenProfileFromMem, cmsCreateTransform, cmsGetTagCount

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small to be a valid ICC profile
    if (size < 128) {
        return 0;
    }

    cmsHPROFILE hProfile = NULL;
    cmsHPROFILE hOutputProfile = NULL;
    cmsHTRANSFORM hTransform = NULL;
    
    // Attempt to open profile from memory
    hProfile = cmsOpenProfileFromMem(data, (cmsUInt32Number)size);
    if (hProfile == NULL) {
        return 0;  // Invalid profile, nothing to process
    }
    
    // Get tag count
    cmsInt32Number tagCount = cmsGetTagCount(hProfile);
    if (tagCount < 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }
    
    // Try to read tags based on available data
    // We'll try to read up to 10 different tag signatures to maximize coverage
    cmsTagSignature tagSignatures[] = {
        cmsSigAToB0Tag, cmsSigAToB1Tag, cmsSigAToB2Tag,
        cmsSigBToA0Tag, cmsSigBToA1Tag, cmsSigBToA2Tag,
        cmsSigBlueColorantTag, cmsSigBlueTRCTag,
        cmsSigBravaisLensDistortionParamsTag, cmsSigCalibrationDateTimeTag
    };
    
    const int numTagsToTry = sizeof(tagSignatures) / sizeof(tagSignatures[0]);
    
    for (int i = 0; i < numTagsToTry && i < tagCount; ++i) {
        void* tagData = cmsReadTag(hProfile, tagSignatures[i]);
        // Don't do anything with the returned data to avoid potential crashes from invalid data
        // Just verify that the call doesn't crash
    }
    
    // For cmsCreateTransform, we need a second profile
    // Let's try creating a minimal sRGB profile as output
    cmsToneCurve* gamma = cmsBuildGamma(NULL, 2.2);
    if (gamma != NULL) {
        cmsCIExyY whitePoint = {0.3127, 0.3290, 1.0};
        cmsCIExyYTRIPLE primaries = {
            {0.6400, 0.3300},  // Red
            {0.3000, 0.6000},  // Green  
            {0.1500, 0.0600}   // Blue
        };
        
        hOutputProfile = cmsCreateRGBProfile(&whitePoint, &primaries, 
                                           (cmsToneCurve**)malloc(sizeof(cmsToneCurve*) * 3));
        
        if (hOutputProfile != NULL) {
            // Create transform from input to our generated output profile
            hTransform = cmsCreateTransform(
                hProfile,          // Input profile
                TYPE_RGB_8,        // Input format
                hOutputProfile,    // Output profile  
                TYPE_RGB_8,        // Output format
                INTENT_PERCEPTUAL, // Rendering intent
                0                  // Flags
            );
            
            // Clean up the transform if created
            if (hTransform != NULL) {
                cmsDeleteTransform(hTransform);
            }
            
            // Close the output profile
            cmsCloseProfile(hOutputProfile);
        }
        
        cmsFreeToneCurve(gamma);
    }
    
    // Close the original profile
    cmsCloseProfile(hProfile);
    
    return 0;
}
