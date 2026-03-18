#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Fuzz driver to test lcms2 color profile creation APIs
// This fuzzer tests the following APIs:
// - cmsCreateLab4Profile
// - cmsCreateRGBProfile
// - cmsCreate_sRGBProfile
// - cmsFreeToneCurve
// - cmsCreateGrayProfile

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early exit if there's not enough data
    if (size < sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE) + 3 * sizeof(cmsToneCurve*)) {
        return 0;
    }

    cmsHPROFILE hLabProfile = nullptr;
    cmsHPROFILE hRGBProfile = nullptr;
    cmsHPROFILE hsRGBProfile = nullptr;
    cmsHPROFILE hGrayProfile = nullptr;
    cmsToneCurve* toneCurves[3] = {nullptr, nullptr, nullptr};
    cmsToneCurve* grayToneCurve = nullptr;

    // Extract data for white point (minimum required size)
    if (size >= sizeof(cmsCIExyY)) {
        cmsCIExyY whitePoint;
        memcpy(&whitePoint, data, sizeof(cmsCIExyY));
        data += sizeof(cmsCIExyY);
        size -= sizeof(cmsCIExyY);

        // Test cmsCreateLab4Profile
        hLabProfile = cmsCreateLab4Profile(&whitePoint);
    } else {
        // Use default white point if not enough data
        cmsCIExyY defaultWhitePoint = {0.3457f, 0.3585f, 1.0f}; // D50
        hLabProfile = cmsCreateLab4Profile(&defaultWhitePoint);
    }

    // Extract data for primaries
    if (size >= sizeof(cmsCIExyYTRIPLE)) {
        cmsCIExyYTRIPLE primaries;
        memcpy(&primaries, data, sizeof(cmsCIExyYTRIPLE));
        data += sizeof(cmsCIExyYTRIPLE);
        size -= sizeof(cmsCIExyYTRIPLE);

        // Create tone curves for RGB profile
        if (size >= sizeof(cmsFloat64Number) * 3) {
            cmsFloat64Number gamma_values[3];
            memcpy(gamma_values, data, sizeof(cmsFloat64Number) * 3);
            
            // Create tone curves for R, G, B channels
            for (int i = 0; i < 3 && i < size / sizeof(cmsFloat64Number); i++) {
                if (gamma_values[i] > 0) {
                    toneCurves[i] = cmsBuildGamma(nullptr, gamma_values[i] > 10.0 ? 1.0 : gamma_values[i]);
                }
            }
        } else {
            // Create default tone curves
            toneCurves[0] = cmsBuildGamma(nullptr, 2.2);
            toneCurves[1] = cmsBuildGamma(nullptr, 2.2);
            toneCurves[2] = cmsBuildGamma(nullptr, 2.2);
        }

        // Test cmsCreateRGBProfile
        hRGBProfile = cmsCreateRGBProfile(&whitePoint, &primaries, toneCurves);
    }

    // Test cmsCreate_sRGBProfile
    hsRGBProfile = cmsCreate_sRGBProfile();

    // Create a tone curve for gray profile
    cmsFloat64Number grayGamma = 2.2f;
    if (size >= sizeof(cmsFloat64Number)) {
        memcpy(&grayGamma, data, sizeof(cmsFloat64Number));
        if (grayGamma <= 0 || grayGamma > 10.0) {
            grayGamma = 2.2f;  // Default value if invalid
        }
    }
    
    grayToneCurve = cmsBuildGamma(nullptr, grayGamma);

    // Test cmsCreateGrayProfile
    hGrayProfile = cmsCreateGrayProfile(&whitePoint, grayToneCurve);

    // Test cmsFreeToneCurve - free the gray tone curve
    if (grayToneCurve) {
        cmsFreeToneCurve(grayToneCurve);
        grayToneCurve = nullptr;
    }

    // Free other tone curves if they were created separately
    for (int i = 0; i < 3; i++) {
        if (toneCurves[i]) {
            cmsFreeToneCurve(toneCurves[i]);
            toneCurves[i] = nullptr;
        }
    }

    // Clean up profiles
    if (hLabProfile) {
        cmsCloseProfile(hLabProfile);
    }
    if (hRGBProfile) {
        cmsCloseProfile(hRGBProfile);
    }
    if (hsRGBProfile) {
        cmsCloseProfile(hsRGBProfile);
    }
    if (hGrayProfile) {
        cmsCloseProfile(hGrayProfile);
    }

    return 0;
}
