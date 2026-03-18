#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver for testing lcms2 APIs: cmsReadTag, cmsCloseProfile, cmsOpenProfileFromFile, cmsWriteTag, cmsSaveProfileToMem

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0; // Need at least some minimal data for the fuzzing
    }

    // Create a temporary profile file from the input data
    FILE* temp_profile = fopen("temp_profile.icc", "wb");
    if (!temp_profile) {
        return 0;
    }
    fwrite(data, 1, size, temp_profile);
    fclose(temp_profile);

    cmsHPROFILE hProfile = NULL;
    cmsHPROFILE hWriteProfile = NULL;
    
    // Try to open the profile from the temporary file
    hProfile = cmsOpenProfileFromFile("temp_profile.icc", "r");
    if (hProfile != NULL) {
        // Test cmsReadTag - try reading common tags
        cmsTagSignature tags_to_try[] = {
            cmsSigAToB0Tag,
            cmsSigAToB1Tag,
            cmsSigAToB2Tag,
            cmsSigBToA0Tag,
            cmsSigBToA1Tag,
            cmsSigBToA2Tag,
            cmsSigRedColorantTag,
            cmsSigGreenColorantTag,
            cmsSigBlueColorantTag,
            cmsSigRedTRCTag,
            cmsSigGreenTRCTag,
            cmsSigBlueTRCTag,
            cmsSigMediaWhitePointTag,
            cmsSigMediaBlackPointTag,
            cmsSigProfileDescriptionTag,
            cmsSigCopyrightTag,
            cmsSigGamutTag,
            cmsSigPreview0Tag,
            cmsSigPreview1Tag,
            cmsSigPreview2Tag
        };
        
        int num_tags = sizeof(tags_to_try) / sizeof(tags_to_try[0]);
        for (int i = 0; i < num_tags; i++) {
            void* tag_data = cmsReadTag(hProfile, tags_to_try[i]);
            // Note: Do not free tag_data as it's owned by the profile
        }

        // Create a new profile for writing tests
        hWriteProfile = cmsCreate_sRGBProfile();
        if (hWriteProfile != NULL) {
            // Test cmsWriteTag - write some simple data
            cmsUInt32Number test_value = 0x12345678;
            
            // Attempt to write the value to a tag (this might fail if the tag is not writable)
            cmsWriteTag(hWriteProfile, cmsSigDeviceMfgDescTag, &test_value);
            
            // Test cmsSaveProfileToMem - first get the required size
            cmsUInt32Number bytes_needed = 0;
            cmsSaveProfileToMem(hWriteProfile, NULL, &bytes_needed);
            
            if (bytes_needed > 0) {
                // Allocate memory for the profile
                void* profile_buffer = malloc(bytes_needed);
                if (profile_buffer != NULL) {
                    cmsSaveProfileToMem(hWriteProfile, profile_buffer, &bytes_needed);
                    free(profile_buffer);
                }
            }
        }

        // Close the original profile
        cmsCloseProfile(hProfile);
    }

    // Close the write profile if created
    if (hWriteProfile != NULL) {
        cmsCloseProfile(hWriteProfile);
    }

    // Clean up temporary file
    remove("temp_profile.icc");

    return 0;
}
