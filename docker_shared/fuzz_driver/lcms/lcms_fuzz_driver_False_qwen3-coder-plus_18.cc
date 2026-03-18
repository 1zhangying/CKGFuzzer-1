#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing lcms2 APIs: cmsReadTag, cmsCloseProfile, cmsWriteTag, cmsSaveProfileToMem, cmsGetTagCount
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) {
        return 0; // Need at least some data to work with
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) {
        return 0;
    }

    // Prepare a temporary profile in memory
    cmsHPROFILE hProfile = NULL;
    cmsIOHANDLER* ioHandler = NULL;
    
    // Attempt to create a profile from the input data
    if (size > 100) { // Only try to load if we have enough data
        ioHandler = cmsOpenIOhandlerFromMem(context, (void*)data, size, "r");
        if (ioHandler) {
            hProfile = cmsOpenProfileFromIOhandlerTHR(context, ioHandler);
            if (!hProfile) {
                cmsCloseIOhandler(ioHandler);
                ioHandler = NULL;
            }
        }
    }
    
    // If we couldn't load a profile from input, create a minimal one
    if (!hProfile) {
        hProfile = cmsCreate_sRGBProfileTHR(context);
        if (!hProfile) {
            cmsDeleteContext(context);
            return 0;
        }
    }

    // Test cmsGetTagCount
    cmsInt32Number tagCount = cmsGetTagCount(hProfile);
    if (tagCount < 0) {
        // Profile might be invalid, continue anyway
        tagCount = 0;
    }

    // Test cmsReadTag with various common tags
    cmsTagSignature commonTags[] = {
        cmsSigRedColorantTag,
        cmsSigGreenColorantTag, 
        cmsSigBlueColorantTag,
        cmsSigMediaWhitePointTag,
        cmsSigMediaBlackPointTag,
        cmsSigProfileDescriptionTag,
        cmsSigCopyrightTag
    };
    
    int numCommonTags = sizeof(commonTags) / sizeof(commonTags[0]);
    
    for (int i = 0; i < numCommonTags && i < tagCount + 5; i++) { // Limit iterations
        cmsTagSignature tagSig = commonTags[i % numCommonTags];
        void* tagData = cmsReadTag(hProfile, tagSig);
        // Don't do anything with tagData since we don't know its type
        // Just verify the function doesn't crash
    }

    // Test cmsWriteTag with sample data
    // First, try to create some sample data based on input
    if (size >= 20) {
        cmsFloat64Number* sampleData = (cmsFloat64Number*)malloc(sizeof(cmsFloat64Number) * 3);
        if (sampleData) {
            memcpy(sampleData, data, sizeof(cmsFloat64Number) * 3 > size - 20 ? size - 20 : sizeof(cmsFloat64Number) * 3);
            
            cmsBool writeResult = cmsWriteTag(hProfile, cmsSigRedColorantTag, sampleData);
            // Ignore result, just make sure function doesn't crash
            
            free(sampleData);
        }
    }

    // Test cmsSaveProfileToMem - first get required size
    cmsUInt32Number bytesNeeded = 0;
    cmsBool sizeResult = cmsSaveProfileToMem(hProfile, NULL, &bytesNeeded);
    
    if (sizeResult && bytesNeeded > 0) {
        // Allocate memory and save the profile
        void* profileBuffer = malloc(bytesNeeded);
        if (profileBuffer) {
            cmsBool saveResult = cmsSaveProfileToMem(hProfile, profileBuffer, &bytesNeeded);
            // Ignore result, just make sure function doesn't crash
            free(profileBuffer);
        }
    }

    // Clean up
    cmsCloseProfile(hProfile);
    
    if (ioHandler) {
        cmsCloseIOhandler(ioHandler);
    }
    
    cmsDeleteContext(context);
    
    return 0;
}
