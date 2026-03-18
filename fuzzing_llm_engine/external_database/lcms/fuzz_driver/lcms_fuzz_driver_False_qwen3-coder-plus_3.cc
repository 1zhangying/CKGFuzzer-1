#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for LCMS2 color management library
// This driver tests various profile creation and transformation APIs

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if input is too small
    if (size < sizeof(cmsFloat64Number) * 6) {
        return 0;
    }

    // Initialize variables from fuzz data
    cmsHPROFILE labProfile = NULL;
    cmsHPROFILE rgbProfile = NULL;
    cmsHPROFILE srgbProfile = NULL;
    cmsHPROFILE grayProfile = NULL;
    cmsHTRANSFORM transform = NULL;
    
    // Extract white point data for Lab profile (2 doubles: x, y)
    cmsFloat64Number labX = 0.0, labY = 0.0, labZ = 1.0;
    if (size >= sizeof(cmsFloat64Number)) {
        memcpy(&labX, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }
    if (size >= sizeof(cmsFloat64Number)) {
        memcpy(&labY, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }

    // Normalize X and Y to valid range [0, 1] for chromaticity
    labX = fmod(fabs(labX), 1.0);
    labY = fmod(fabs(labY), 1.0);
    
    // Create Lab profile with extracted white point
    cmsCIExyY labWhitePoint = { labX, labY, labZ };
    labProfile = cmsCreateLab4Profile(&labWhitePoint);
    
    // Extract more data for RGB profile
    cmsFloat64Number rgbX = 0.3127, rgbY = 0.3290, rgbZ = 1.0;  // D65 default
    if (size >= sizeof(cmsFloat64Number)) {
        memcpy(&rgbX, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }
    if (size >= sizeof(cmsFloat64Number)) {
        memcpy(&rgbY, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }
    
    // Normalize X and Y to valid range [0, 1]
    rgbX = fmod(fabs(rgbX), 1.0);
    rgbY = fmod(fabs(rgbY), 1.0);
    
    cmsCIExyY rgbWhitePoint = { rgbX, rgbY, rgbZ };
    
    // Extract RGB primaries data (3 sets of xyY coordinates)
    cmsCIExyYTRIPLE primaries = {{0}};
    if (size >= sizeof(cmsFloat64Number) * 2) {
        memcpy(&primaries.Red.x, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
        memcpy(&primaries.Red.y, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }
    if (size >= sizeof(cmsFloat64Number) * 2) {
        memcpy(&primaries.Green.x, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
        memcpy(&primaries.Green.y, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }
    if (size >= sizeof(cmsFloat64Number) * 2) {
        memcpy(&primaries.Blue.x, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
        memcpy(&primaries.Blue.y, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }
    
    // Normalize primaries to valid range
    primaries.Red.x = fmod(fabs(primaries.Red.x), 1.0);
    primaries.Red.y = fmod(fabs(primaries.Red.y), 1.0);
    primaries.Green.x = fmod(fabs(primaries.Green.x), 1.0);
    primaries.Green.y = fmod(fabs(primaries.Green.y), 1.0);
    primaries.Blue.x = fmod(fabs(primaries.Blue.x), 1.0);
    primaries.Blue.y = fmod(fabs(primaries.Blue.y), 1.0);
    primaries.Red.Y = primaries.Green.Y = primaries.Blue.Y = 1.0;
    
    // Create tone curves for RGB profile (using basic gamma curves)
    cmsFloat64Number gamma = 2.2;
    if (size >= sizeof(cmsFloat64Number)) {
        memcpy(&gamma, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }
    
    // Ensure gamma is positive to avoid invalid curve
    gamma = fmax(0.1, fabs(gamma));
    
    cmsToneCurve* transferFunctions[3];
    transferFunctions[0] = cmsBuildGamma(NULL, gamma);  // Red
    transferFunctions[1] = cmsBuildGamma(NULL, gamma);  // Green
    transferFunctions[2] = cmsBuildGamma(NULL, gamma);  // Blue
    
    // Create RGB profile
    rgbProfile = cmsCreateRGBProfile(&rgbWhitePoint, &primaries, transferFunctions);
    
    // Create sRGB profile (no parameters needed)
    srgbProfile = cmsCreate_sRGBProfile();
    
    // Extract data for gray profile
    cmsFloat64Number grayX = 0.3127, grayY = 0.3290, grayZ = 1.0;  // D65 default
    if (size >= sizeof(cmsFloat64Number)) {
        memcpy(&grayX, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }
    if (size >= sizeof(cmsFloat64Number)) {
        memcpy(&grayY, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }
    
    // Normalize X and Y to valid range [0, 1]
    grayX = fmod(fabs(grayX), 1.0);
    grayY = fmod(fabs(grayY), 1.0);
    
    cmsCIExyY grayWhitePoint = { grayX, grayY, grayZ };
    
    // Create tone curve for gray profile
    cmsFloat64Number grayGamma = 2.2;
    if (size >= sizeof(cmsFloat64Number)) {
        memcpy(&grayGamma, data, sizeof(cmsFloat64Number));
        data += sizeof(cmsFloat64Number);
        size -= sizeof(cmsFloat64Number);
    }
    
    // Ensure gamma is positive
    grayGamma = fmax(0.1, fabs(grayGamma));
    
    cmsToneCurve* grayTransferFunction = cmsBuildGamma(NULL, grayGamma);
    
    // Create gray profile
    grayProfile = cmsCreateGrayProfile(&grayWhitePoint, grayTransferFunction);
    
    // Create a transform using the created profiles
    if (rgbProfile && srgbProfile) {
        // Use remaining bytes to determine format and intent
        cmsUInt32Number inputFormat = TYPE_RGB_8;
        cmsUInt32Number outputFormat = TYPE_RGB_8;
        cmsUInt32Number intent = INTENT_PERCEPTUAL;
        cmsUInt32Number flags = 0;
        
        if (size >= sizeof(cmsUInt32Number)) {
            memcpy(&inputFormat, data, sizeof(cmsUInt32Number));
            data += sizeof(cmsUInt32Number);
            size -= sizeof(cmsUInt32Number);
        }
        if (size >= sizeof(cmsUInt32Number)) {
            memcpy(&outputFormat, data, sizeof(cmsUInt32Number));
            data += sizeof(cmsUInt32Number);
            size -= sizeof(cmsUInt32Number);
        }
        if (size >= sizeof(cmsUInt32Number)) {
            memcpy(&intent, data, sizeof(cmsUInt32Number));
            data += sizeof(cmsUInt32Number);
            size -= sizeof(cmsUInt32Number);
        }
        if (size >= sizeof(cmsUInt32Number)) {
            memcpy(&flags, data, sizeof(cmsUInt32Number));
            // Don't consume this data as we might need to reset
        }
        
        // Limit intent to valid range
        intent = intent % 4;  // Only 4 intents supported
        
        transform = cmsCreateTransform(rgbProfile, inputFormat, 
                                      srgbProfile, outputFormat, 
                                      intent, flags);
    }
    
    // Perform some operations with the transform if it was created
    if (transform) {
        // Allocate buffers for testing
        unsigned char srcBuffer[256 * 3];  // RGB data for 256 pixels
        unsigned char dstBuffer[256 * 3];  // RGB data for 256 pixels
        
        // Initialize source buffer with data from fuzz input (if available)
        size_t srcSize = sizeof(srcBuffer);
        if (size > 0) {
            size_t copySize = (size < srcSize) ? size : srcSize;
            memcpy(srcBuffer, data, copySize);
        } else {
            // Fill with pattern if not enough data
            for (size_t i = 0; i < srcSize; ++i) {
                srcBuffer[i] = static_cast<unsigned char>(i % 256);
            }
        }
        
        // Apply the transform
        cmsDoTransform(transform, srcBuffer, dstBuffer, 256);
    }
    
    // Clean up all created resources
    if (transform) {
        cmsDeleteTransform(transform);
    }
    
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
    if (transferFunctions[0]) {
        cmsFreeToneCurve(transferFunctions[0]);
    }
    if (transferFunctions[1]) {
        cmsFreeToneCurve(transferFunctions[1]);
    }
    if (transferFunctions[2]) {
        cmsFreeToneCurve(transferFunctions[2]);
    }
    
    if (grayTransferFunction) {
        cmsFreeToneCurve(grayTransferFunction);
    }
    
    return 0;
}
