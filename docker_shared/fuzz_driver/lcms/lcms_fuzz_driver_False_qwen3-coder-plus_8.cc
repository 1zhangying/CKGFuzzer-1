#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing lcms2 APIs
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables to avoid undefined behavior
    cmsHPROFILE labProfile = NULL;
    cmsHPROFILE rgbProfile = NULL;
    cmsHPROFILE srgbProfile = NULL;
    cmsHPROFILE grayProfile = NULL;
    cmsHPROFILE memProfile = NULL;
    cmsCIExyY whitePoint = {0};
    cmsCIExyYTRIPLE primaries = {0};
    cmsToneCurve* transferFunctions[3] = {NULL, NULL, NULL};
    cmsToneCurve* grayTransferFunction = NULL;
    void* tagData = NULL;
    
    // Ensure minimum size for processing
    if (size < sizeof(cmsCIExyY) * 2 + sizeof(cmsToneCurve*)) {
        return 0;
    }
    
    size_t offset = 0;
    
    // Extract white point for Lab profile (minimum 8 bytes needed)
    if (offset + sizeof(cmsCIExyY) <= size) {
        memcpy(&whitePoint, data + offset, sizeof(cmsCIExyY));
        offset += sizeof(cmsCIExyY);
        
        // Create Lab profile
        labProfile = cmsCreateLab4Profile(&whitePoint);
    }
    
    // Extract white point for RGB profile
    cmsCIExyY rgbWhitePoint = {0};
    if (offset + sizeof(cmsCIExyY) <= size) {
        memcpy(&rgbWhitePoint, data + offset, sizeof(cmsCIExyY));
        offset += sizeof(cmsCIExyY);
    }
    
    // Extract primaries for RGB profile
    if (offset + sizeof(cmsCIExyYTRIPLE) <= size) {
        memcpy(&primaries, data + offset, sizeof(cmsCIExyYTRIPLE));
        offset += sizeof(cmsCIExyYTRIPLE);
    }
    
    // Create RGB profile if we have enough data
    if (labProfile != NULL) {
        // Create some tone curves for RGB profile using remaining data
        if (size > offset) {
            cmsFloat64Number params[10] = {0};
            size_t paramCount = (size - offset) / sizeof(cmsFloat64Number);
            if (paramCount > 10) paramCount = 10;
            
            if (paramCount > 0) {
                for (size_t i = 0; i < paramCount && i < 10; i++) {
                    memcpy(&params[i], data + offset + i * sizeof(cmsFloat64Number), 
                           sizeof(cmsFloat64Number));
                }
                
                // Create tone curves for RGB channels
                transferFunctions[0] = cmsBuildParametricToneCurve(NULL, 1, params);
                transferFunctions[1] = cmsBuildParametricToneCurve(NULL, 1, params);
                transferFunctions[2] = cmsBuildParametricToneCurve(NULL, 1, params);
                
                rgbProfile = cmsCreateRGBProfile(&rgbWhitePoint, &primaries, transferFunctions);
            }
        }
    }
    
    // Create sRGB profile
    srgbProfile = cmsCreate_sRGBProfile();
    
    // Create gray profile with extracted white point
    if (offset + sizeof(cmsCIExyY) <= size) {
        cmsCIExyY grayWhitePoint = {0};
        memcpy(&grayWhitePoint, data + offset, sizeof(cmsCIExyY));
        
        // Create a simple gamma curve for gray profile
        cmsFloat64Number gamma = 2.2;
        grayTransferFunction = cmsBuildGamma(NULL, gamma);
        
        if (grayTransferFunction != NULL) {
            grayProfile = cmsCreateGrayProfile(&grayWhitePoint, grayTransferFunction);
        }
    }
    
    // Try to open profile from memory if there's sufficient data
    if (size > 100) { // Need at least minimal ICC profile size
        memProfile = cmsOpenProfileFromMem(data, (cmsUInt32Number)size);
    }
    
    // Test cmsReadTag with various profiles and tag signatures
    if (labProfile != NULL) {
        // Try to read common tags from the lab profile
        tagData = cmsReadTag(labProfile, cmsSigMediaWhitePointTag);
        tagData = cmsReadTag(labProfile, cmsSigProfileDescriptionTag); // Reuse variable
        tagData = cmsReadTag(labProfile, cmsSigCopyrightTag); // Reuse variable
    }
    
    if (rgbProfile != NULL) {
        tagData = cmsReadTag(rgbProfile, cmsSigRedColorantTag);
        tagData = cmsReadTag(rgbProfile, cmsSigGreenColorantTag); // Reuse variable
        tagData = cmsReadTag(rgbProfile, cmsSigBlueColorantTag); // Reuse variable
    }
    
    if (srgbProfile != NULL) {
        tagData = cmsReadTag(srgbProfile, cmsSigAToB0Tag);
        tagData = cmsReadTag(srgbProfile, cmsSigBToA0Tag); // Reuse variable
    }
    
    if (grayProfile != NULL) {
        tagData = cmsReadTag(grayProfile, cmsSigGrayTRCTag);
    }
    
    if (memProfile != NULL) {
        tagData = cmsReadTag(memProfile, cmsSigDeviceMfgDescTag);
        tagData = cmsReadTag(memProfile, cmsSigDeviceModelDescTag); // Reuse variable
    }
    
    // Clean up resources
    if (transferFunctions[0] != NULL) cmsFreeToneCurve(transferFunctions[0]);
    if (transferFunctions[1] != NULL) cmsFreeToneCurve(transferFunctions[1]);
    if (transferFunctions[2] != NULL) cmsFreeToneCurve(transferFunctions[2]);
    if (grayTransferFunction != NULL) cmsFreeToneCurve(grayTransferFunction);
    
    if (labProfile != NULL) cmsCloseProfile(labProfile);
    if (rgbProfile != NULL) cmsCloseProfile(rgbProfile);
    if (srgbProfile != NULL) cmsCloseProfile(srgbProfile);
    if (grayProfile != NULL) cmsCloseProfile(grayProfile);
    if (memProfile != NULL) cmsCloseProfile(memProfile);
    
    return 0;
}
