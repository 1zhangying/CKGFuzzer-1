#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for lcms2 library testing
// This fuzzer tests various color profile and transform APIs
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 100) {  // Need minimum size for meaningful tests
        return 0;
    }

    cmsHPROFILE hProfile1 = NULL;
    cmsHPROFILE hProfile2 = NULL;
    cmsHPROFILE hProfile3 = NULL;
    cmsHTRANSFORM hTransform = NULL;
    cmsHTRANSFORM hMultiTransform = NULL;
    cmsHTRANSFORM hProofTransform = NULL;

    // Extract initial data for profile creation
    size_t profile1_size = size / 3;
    if (profile1_size < 10) profile1_size = 10;
    
    size_t profile2_start = profile1_size;
    size_t profile2_size = (size - profile2_start) / 2;
    if (profile2_size < 10) profile2_size = 10;
    
    size_t profile3_start = profile2_start + profile2_size;
    size_t profile3_size = size - profile3_start;
    if (profile3_size < 10) profile3_size = 10;

    // Try to open profiles from memory
    hProfile1 = cmsOpenProfileFromMem(data, profile1_size);
    if (hProfile1 == NULL) {
        goto cleanup;
    }

    hProfile2 = cmsOpenProfileFromMem(data + profile2_start, profile2_size);
    if (hProfile2 == NULL) {
        goto cleanup;
    }
    
    hProfile3 = cmsOpenProfileFromMem(data + profile3_start, profile3_size);
    if (hProfile3 == NULL) {
        goto cleanup;
    }

    // Extract parameters for transform creation from remaining data
    size_t offset = profile3_start + profile3_size;
    if (offset >= size) offset = 0;
    
    // Use remaining bytes to determine format, intent, and flags
    cmsUInt32Number input_format = 0x18000000; // Default RGBA_8
    cmsUInt32Number output_format = 0x18000000; // Default RGBA_8
    cmsUInt32Number intent = 0; // Perceptual intent
    cmsUInt32Number flags = 0; // No special flags
    
    if (size - offset >= 16) {
        input_format = *(uint32_t*)(data + offset) % 0x100000000;
        output_format = *(uint32_t*)(data + offset + 4) % 0x100000000;
        intent = *(uint32_t*)(data + offset + 8) % 4; // Valid intents are 0-3
        flags = *(uint32_t*)(data + offset + 12) % 0x100000000;
    }

    // Test cmsCreateTransform
    hTransform = cmsCreateTransform(hProfile1, input_format, hProfile2, output_format, intent, flags);
    if (hTransform != NULL) {
        // Prepare dummy input/output buffers for cmsDoTransform
        cmsUInt32Number pixel_count = 10;
        size_t input_buffer_size = pixel_count * cmsChannelsOf(cmsGetColorSpace(hProfile1)) * sizeof(cmsUInt8Number);
        size_t output_buffer_size = pixel_count * cmsChannelsOf(cmsGetColorSpace(hProfile2)) * sizeof(cmsUInt8Number);
        
        if (input_buffer_size == 0) input_buffer_size = pixel_count * 4; // Default to RGBA
        if (output_buffer_size == 0) output_buffer_size = pixel_count * 4; // Default to RGBA
        
        cmsUInt8Number* input_buffer = (cmsUInt8Number*)malloc(input_buffer_size);
        cmsUInt8Number* output_buffer = (cmsUInt8Number*)malloc(output_buffer_size);
        
        if (input_buffer && output_buffer) {
            // Initialize buffers with sample data from fuzz input
            memset(input_buffer, 0, input_buffer_size);
            size_t copy_size = (input_buffer_size < size - offset - 16) ? input_buffer_size : size - offset - 16;
            if (copy_size > 0 && offset + 16 + copy_size <= size) {
                memcpy(input_buffer, data + offset + 16, copy_size);
            }
            
            // Perform the transform
            cmsDoTransform(hTransform, input_buffer, output_buffer, pixel_count);
        }
        
        if (input_buffer) free(input_buffer);
        if (output_buffer) free(output_buffer);
        
        // Clean up transform
        cmsDeleteTransform(hTransform);
        hTransform = NULL;
    }

    // Test cmsCreateMultiprofileTransform
    cmsHPROFILE profiles[] = {hProfile1, hProfile2, hProfile3};
    cmsUInt32Number n_profiles = 3;
    
    hMultiTransform = cmsCreateMultiprofileTransform(profiles, n_profiles, input_format, output_format, intent, flags);
    if (hMultiTransform != NULL) {
        // Prepare dummy input/output buffers for cmsDoTransform
        cmsUInt32Number pixel_count = 5;
        size_t input_buffer_size = pixel_count * cmsChannelsOf(cmsGetColorSpace(hProfile1)) * sizeof(cmsUInt8Number);
        size_t output_buffer_size = pixel_count * cmsChannelsOf(cmsGetColorSpace(hProfile3)) * sizeof(cmsUInt8Number);
        
        if (input_buffer_size == 0) input_buffer_size = pixel_count * 4; // Default to RGBA
        if (output_buffer_size == 0) output_buffer_size = pixel_count * 4; // Default to RGBA
        
        cmsUInt8Number* input_buffer = (cmsUInt8Number*)malloc(input_buffer_size);
        cmsUInt8Number* output_buffer = (cmsUInt8Number*)malloc(output_buffer_size);
        
        if (input_buffer && output_buffer) {
            // Initialize buffers with sample data
            memset(input_buffer, 0, input_buffer_size);
            memset(output_buffer, 0, output_buffer_size);
            
            // Perform the transform
            cmsDoTransform(hMultiTransform, input_buffer, output_buffer, pixel_count);
        }
        
        if (input_buffer) free(input_buffer);
        if (output_buffer) free(output_buffer);
        
        // Clean up transform
        cmsDeleteTransform(hMultiTransform);
        hMultiTransform = NULL;
    }

    // Test cmsCreateProofingTransform
    hProofTransform = cmsCreateProofingTransform(hProfile1, input_format, hProfile2, output_format, hProfile3, intent, intent, flags);
    if (hProofTransform != NULL) {
        // Prepare dummy input/output buffers for cmsDoTransform
        cmsUInt32Number pixel_count = 5;
        size_t input_buffer_size = pixel_count * cmsChannelsOf(cmsGetColorSpace(hProfile1)) * sizeof(cmsUInt8Number);
        size_t output_buffer_size = pixel_count * cmsChannelsOf(cmsGetColorSpace(hProfile2)) * sizeof(cmsUInt8Number);
        
        if (input_buffer_size == 0) input_buffer_size = pixel_count * 4; // Default to RGBA
        if (output_buffer_size == 0) output_buffer_size = pixel_count * 4; // Default to RGBA
        
        cmsUInt8Number* input_buffer = (cmsUInt8Number*)malloc(input_buffer_size);
        cmsUInt8Number* output_buffer = (cmsUInt8Number*)malloc(output_buffer_size);
        
        if (input_buffer && output_buffer) {
            // Initialize buffers with sample data
            memset(input_buffer, 0, input_buffer_size);
            memset(output_buffer, 0, output_buffer_size);
            
            // Perform the transform
            cmsDoTransform(hProofTransform, input_buffer, output_buffer, pixel_count);
        }
        
        if (input_buffer) free(input_buffer);
        if (output_buffer) free(output_buffer);
        
        // Clean up transform
        cmsDeleteTransform(hProofTransform);
        hProofTransform = NULL;
    }

cleanup:
    // Clean up profiles
    if (hProfile1) cmsCloseProfile(hProfile1);
    if (hProfile2) cmsCloseProfile(hProfile2);
    if (hProfile3) cmsCloseProfile(hProfile3);

    // Clean up transforms if they weren't already cleaned up
    if (hTransform) cmsDeleteTransform(hTransform);
    if (hMultiTransform) cmsDeleteTransform(hMultiTransform);
    if (hProofTransform) cmsDeleteTransform(hProofTransform);

    return 0;
}
