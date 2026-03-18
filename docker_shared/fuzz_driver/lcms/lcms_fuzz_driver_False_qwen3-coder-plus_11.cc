#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing lcms2 APIs: cmsReadTag, cmsCreateLab4Profile, cmsCreateRGBProfile, 
// cmsIT8LoadFromMem, cmsCreateGrayProfile, cmsFreeToneCurve
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables to avoid undefined behavior
    cmsHPROFILE labProfile = NULL;
    cmsHPROFILE rgbProfile = NULL;
    cmsHPROFILE grayProfile = NULL;
    cmsHANDLE it8Handle = NULL;
    cmsToneCurve* toneCurves[3] = {NULL, NULL, NULL};
    cmsToneCurve* grayToneCurve = NULL;
    cmsCIExyY whitePoint = {0.0, 0.0, 0.0};
    cmsCIExyYTRIPLE primaries = {{0.0, 0.0, 0.0}, {0.0, 0.0, 0.0}, {0.0, 0.0, 0.0}};
    void* tagData = NULL;
    
    // Early exit if input size is too small
    if (size < sizeof(cmsTagSignature)) {
        return 0;
    }
    
    // Extract values from input data for various purposes
    size_t offset = 0;
    
    // Extract white point for Lab profile (minimum 6 doubles needed)
    if (size >= offset + 6 * sizeof(double)) {
        whitePoint.X = *(double*)(data + offset);
        offset += sizeof(double);
        whitePoint.Y = *(double*)(data + offset);
        offset += sizeof(double);
        whitePoint.Z = *(double*)(data + offset);
        offset += sizeof(double);
        
        // Create Lab profile with the extracted white point
        labProfile = cmsCreateLab4Profile(&whitePoint);
    }
    
    // Extract RGB primaries if enough data remains
    if (size >= offset + 12 * sizeof(double)) {
        // Red primary
        primaries.Red.X = *(double*)(data + offset);
        offset += sizeof(double);
        primaries.Red.Y = *(double*)(data + offset);
        offset += sizeof(double);
        primaries.Red.Z = *(double*)(data + offset);
        offset += sizeof(double);
        
        // Green primary
        primaries.Green.X = *(double*)(data + offset);
        offset += sizeof(double);
        primaries.Green.Y = *(double*)(data + offset);
        offset += sizeof(double);
        primaries.Green.Z = *(double*)(data + offset);
        offset += sizeof(double);
        
        // Blue primary
        primaries.Blue.X = *(double*)(data + offset);
        offset += sizeof(double);
        primaries.Blue.Y = *(double*)(data + offset);
        offset += sizeof(double);
        primaries.Blue.Z = *(double*)(data + offset);
        offset += sizeof(double);
    }
    
    // Create tone curves for RGB profile if we have enough data
    if (size >= offset + 3 * sizeof(double)) {
        double gamma1 = *(double*)(data + offset);
        offset += sizeof(double);
        double gamma2 = *(double*)(data + offset);
        offset += sizeof(double);
        double gamma3 = *(double*)(data + offset);
        offset += sizeof(double);
        
        // Create tone curves with gamma values (ensure gamma > 0)
        if (gamma1 > 0.0) toneCurves[0] = cmsBuildGamma(NULL, gamma1);
        if (gamma2 > 0.0) toneCurves[1] = cmsBuildGamma(NULL, gamma2);
        if (gamma3 > 0.0) toneCurves[2] = cmsBuildGamma(NULL, gamma3);
        
        // Create RGB profile
        rgbProfile = cmsCreateRGBProfile(&whitePoint, &primaries, toneCurves);
    }
    
    // Create tone curve for gray profile if we have more data
    if (size >= offset + sizeof(double)) {
        double grayGamma = *(double*)(data + offset);
        offset += sizeof(double);
        
        if (grayGamma > 0.0) {
            grayToneCurve = cmsBuildGamma(NULL, grayGamma);
            if (grayToneCurve) {
                grayProfile = cmsCreateGrayProfile(&whitePoint, grayToneCurve);
            }
        }
    }
    
    // Try to load IT8 data from remaining portion of input if available
    if (size > offset) {
        size_t remainingSize = size - offset;
        if (remainingSize > 0) {
            it8Handle = cmsIT8LoadFromMem(NULL, (const void*)(data + offset), (cmsUInt32Number)remainingSize);
        }
    }
    
    // Test cmsReadTag with Lab profile if created
    if (labProfile) {
        // Try to read a common tag from the Lab profile
        tagData = cmsReadTag(labProfile, cmsSigMediaWhitePointTag);
        // Note: tagData points to internal profile data, do not free it directly
    }
    
    // Test cmsReadTag with RGB profile if created
    if (rgbProfile) {
        tagData = cmsReadTag(rgbProfile, cmsSigRedColorantTag);
    }
    
    // Test cmsReadTag with Gray profile if created
    if (grayProfile) {
        tagData = cmsReadTag(grayProfile, cmsSigGrayTRCTag);
    }
    
    // Clean up resources in reverse order of creation
    if (it8Handle) {
        cmsIT8Free(it8Handle);
    }
    
    if (grayProfile) {
        cmsCloseProfile(grayProfile);
    }
    
    if (rgbProfile) {
        cmsCloseProfile(rgbProfile);
    }
    
    if (labProfile) {
        cmsCloseProfile(labProfile);
    }
    
    // Free tone curves if they were allocated
    for (int i = 0; i < 3; i++) {
        if (toneCurves[i]) {
            cmsFreeToneCurve(toneCurves[i]);
        }
    }
    
    if (grayToneCurve) {
        cmsFreeToneCurve(grayToneCurve);
    }
    
    return 0;
}
