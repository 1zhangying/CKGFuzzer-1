#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing lcms2 APIs: cmsReadTag, cmsOpenProfileFromMem, cmsWriteTag, cmsFreeToneCurve, cmsGetTagCount
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if size is too small to contain meaningful profile data
    if (size < 128) {
        return 0;
    }

    cmsHPROFILE hProfile = nullptr;
    cmsToneCurve* toneCurve = nullptr;
    cmsFloat32Number* curveValues = nullptr;
    
    // Open profile from memory
    hProfile = cmsOpenProfileFromMem(data, static_cast<cmsUInt32Number>(size));
    if (hProfile != nullptr) {
        // Get tag count
        cmsInt32Number tagCount = cmsGetTagCount(hProfile);
        
        // If there are tags, try to read one
        if (tagCount > 0) {
            // Attempt to read a common tag type - cmsSigAToB0Tag
            cmsTagSignature tagSig = cmsSigAToB0Tag;
            void* tagData = cmsReadTag(hProfile, tagSig);
            
            // If tag exists and is a tone curve, we'll try to write a new one later
            // For now, just test reading functionality
        }
        
        // Prepare some data to write as a tone curve
        // Allocate and initialize a simple tone curve
        cmsUInt32Number nPoints = 256;
        curveValues = (cmsFloat32Number*)malloc(nPoints * sizeof(cmsFloat32Number));
        if (curveValues != nullptr) {
            for (cmsUInt32Number i = 0; i < nPoints; i++) {
                curveValues[i] = static_cast<cmsFloat32Number>(i) / (nPoints - 1);
            }
            
            toneCurve = cmsBuildTabularToneCurveFloat(nullptr, nPoints, curveValues);
            if (toneCurve != nullptr) {
                // Write the tone curve to the profile
                cmsBool writeResult = cmsWriteTag(hProfile, cmsSigVcgtTag, toneCurve);
                
                // Try to read it back
                cmsToneCurve* readCurve = (cmsToneCurve*)cmsReadTag(hProfile, cmsSigVcgtTag);
                // Note: We don't free readCurve as it's managed internally by the profile
                
                // Write another tag with different signature
                cmsWriteTag(hProfile, cmsSigBlueTRCTag, toneCurve);
            }
        }
        
        // Free the allocated tone curve
        if (toneCurve != nullptr) {
            cmsFreeToneCurve(toneCurve);
            toneCurve = nullptr;
        }
        
        // Close the profile
        cmsCloseProfile(hProfile);
    }
    
    // Test with different tag signatures based on input data
    if (size >= sizeof(cmsTagSignature) + 1) {
        // Use part of the input data to determine which tag to operate on
        cmsTagSignature customTag = *(cmsTagSignature*)(data + size - sizeof(cmsTagSignature));
        
        // Reopen profile to test with different tag
        hProfile = cmsOpenProfileFromMem(data, static_cast<cmsUInt32Number>(size - sizeof(cmsTagSignature)));
        if (hProfile != nullptr) {
            // Try to read the custom tag
            void* customTagData = cmsReadTag(hProfile, customTag);
            
            // If we have enough data, try to write something
            if (size > sizeof(cmsTagSignature) + 10) {
                cmsWriteTag(hProfile, customTag, data + sizeof(cmsTagSignature));
            }
            
            cmsCloseProfile(hProfile);
        }
    }
    
    // Clean up
    if (curveValues != nullptr) {
        free(curveValues);
        curveValues = nullptr;
    }
    
    return 0;
}
