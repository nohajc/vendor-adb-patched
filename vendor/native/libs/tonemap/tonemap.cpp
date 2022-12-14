/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <tonemap/tonemap.h>

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <type_traits>

namespace android::tonemap {

namespace {

// Flag containing the variant of tone map algorithm to use.
enum class ToneMapAlgorithm {
    AndroidO,  // Default algorithm in place since Android O,
    Android13, // Algorithm used in Android 13.
};

static const constexpr auto kToneMapAlgorithm = ToneMapAlgorithm::Android13;

static const constexpr auto kTransferMask =
        static_cast<int32_t>(aidl::android::hardware::graphics::common::Dataspace::TRANSFER_MASK);
static const constexpr auto kTransferST2084 =
        static_cast<int32_t>(aidl::android::hardware::graphics::common::Dataspace::TRANSFER_ST2084);
static const constexpr auto kTransferHLG =
        static_cast<int32_t>(aidl::android::hardware::graphics::common::Dataspace::TRANSFER_HLG);

template <typename T, std::enable_if_t<std::is_trivially_copyable<T>::value, bool> = true>
std::vector<uint8_t> buildUniformValue(T value) {
    std::vector<uint8_t> result;
    result.resize(sizeof(value));
    std::memcpy(result.data(), &value, sizeof(value));
    return result;
}

// Refer to BT2100-2
float computeHlgGamma(float currentDisplayBrightnessNits) {
    // BT 2100-2's recommendation for taking into account the nominal max
    // brightness of the display does not work when the current brightness is
    // very low. For instance, the gamma becomes negative when the current
    // brightness is between 1 and 2 nits, which would be a bad experience in a
    // dark environment. Furthermore, BT2100-2 recommends applying
    // channel^(gamma - 1) as its OOTF, which means that when the current
    // brightness is lower than 335 nits then channel * channel^(gamma - 1) >
    // channel, which makes dark scenes very bright. As a workaround for those
    // problems, lower-bound the brightness to 500 nits.
    constexpr float minBrightnessNits = 500.f;
    currentDisplayBrightnessNits = std::max(minBrightnessNits, currentDisplayBrightnessNits);
    return 1.2 + 0.42 * std::log10(currentDisplayBrightnessNits / 1000);
}

class ToneMapperO : public ToneMapper {
public:
    std::string generateTonemapGainShaderSkSL(
            aidl::android::hardware::graphics::common::Dataspace sourceDataspace,
            aidl::android::hardware::graphics::common::Dataspace destinationDataspace) override {
        const int32_t sourceDataspaceInt = static_cast<int32_t>(sourceDataspace);
        const int32_t destinationDataspaceInt = static_cast<int32_t>(destinationDataspace);

        std::string program;
        // Define required uniforms
        program.append(R"(
                uniform float in_libtonemap_displayMaxLuminance;
                uniform float in_libtonemap_inputMaxLuminance;
            )");
        switch (sourceDataspaceInt & kTransferMask) {
            case kTransferST2084:
            case kTransferHLG:
                switch (destinationDataspaceInt & kTransferMask) {
                    case kTransferST2084:
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(vec3 xyz) {
                                        return xyz.y;
                                    }
                                )");
                        break;
                    case kTransferHLG:
                        // PQ has a wider luminance range (10,000 nits vs. 1,000 nits) than HLG, so
                        // we'll clamp the luminance range in case we're mapping from PQ input to
                        // HLG output.
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(vec3 xyz) {
                                        float nits = clamp(xyz.y, 0.0, 1000.0);
                                        return nits * pow(nits / 1000.0, -0.2 / 1.2);
                                    }
                                )");
                        break;
                    default:
                        // HLG follows BT2100, but this tonemapping version
                        // does not take into account current display brightness
                        if ((sourceDataspaceInt & kTransferMask) == kTransferHLG) {
                            program.append(R"(
                                        float libtonemap_applyBaseOOTFGain(float nits) {
                                            return pow(nits, 0.2);
                                        }
                                    )");
                        } else {
                            program.append(R"(
                                        float libtonemap_applyBaseOOTFGain(float nits) {
                                            return 1.0;
                                        }
                                    )");
                        }
                        // Here we're mapping from HDR to SDR content, so interpolate using a
                        // Hermitian polynomial onto the smaller luminance range.
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(vec3 xyz) {
                                        float maxInLumi = in_libtonemap_inputMaxLuminance;
                                        float maxOutLumi = in_libtonemap_displayMaxLuminance;

                                        xyz = xyz * libtonemap_applyBaseOOTFGain(xyz.y);

                                        float nits = xyz.y;

                                        // if the max input luminance is less than what we can
                                        // output then no tone mapping is needed as all color
                                        // values will be in range.
                                        if (maxInLumi <= maxOutLumi) {
                                            return xyz.y;
                                        } else {

                                            // three control points
                                            const float x0 = 10.0;
                                            const float y0 = 17.0;
                                            float x1 = maxOutLumi * 0.75;
                                            float y1 = x1;
                                            float x2 = x1 + (maxInLumi - x1) / 2.0;
                                            float y2 = y1 + (maxOutLumi - y1) * 0.75;

                                            // horizontal distances between the last three
                                            // control points
                                            float h12 = x2 - x1;
                                            float h23 = maxInLumi - x2;
                                            // tangents at the last three control points
                                            float m1 = (y2 - y1) / h12;
                                            float m3 = (maxOutLumi - y2) / h23;
                                            float m2 = (m1 + m3) / 2.0;

                                            if (nits < x0) {
                                                // scale [0.0, x0] to [0.0, y0] linearly
                                                float slope = y0 / x0;
                                                return nits * slope;
                                            } else if (nits < x1) {
                                                // scale [x0, x1] to [y0, y1] linearly
                                                float slope = (y1 - y0) / (x1 - x0);
                                                nits = y0 + (nits - x0) * slope;
                                            } else if (nits < x2) {
                                                // scale [x1, x2] to [y1, y2] using Hermite interp
                                                float t = (nits - x1) / h12;
                                                nits = (y1 * (1.0 + 2.0 * t) + h12 * m1 * t) *
                                                        (1.0 - t) * (1.0 - t) +
                                                        (y2 * (3.0 - 2.0 * t) +
                                                        h12 * m2 * (t - 1.0)) * t * t;
                                            } else {
                                                // scale [x2, maxInLumi] to [y2, maxOutLumi] using
                                                // Hermite interp
                                                float t = (nits - x2) / h23;
                                                nits = (y2 * (1.0 + 2.0 * t) + h23 * m2 * t) *
                                                        (1.0 - t) * (1.0 - t) + (maxOutLumi *
                                                        (3.0 - 2.0 * t) + h23 * m3 *
                                                        (t - 1.0)) * t * t;
                                            }
                                        }

                                        return nits;
                                    }
                                )");
                        break;
                }
                break;
            default:
                switch (destinationDataspaceInt & kTransferMask) {
                    case kTransferST2084:
                    case kTransferHLG:
                        // HLG follows BT2100, but this tonemapping version
                        // does not take into account current display brightness
                        if ((destinationDataspaceInt & kTransferMask) == kTransferHLG) {
                            program.append(R"(
                                        float libtonemap_applyBaseOOTFGain(float nits) {
                                            return pow(nits / 1000.0, -0.2 / 1.2);
                                        }
                                    )");
                        } else {
                            program.append(R"(
                                        float libtonemap_applyBaseOOTFGain(float nits) {
                                            return 1.0;
                                        }
                                    )");
                        }
                        // Map from SDR onto an HDR output buffer
                        // Here we use a polynomial curve to map from [0, displayMaxLuminance] onto
                        // [0, maxOutLumi] which is hard-coded to be 3000 nits.
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(vec3 xyz) {
                                        const float maxOutLumi = 3000.0;

                                        const float x0 = 5.0;
                                        const float y0 = 2.5;
                                        float x1 = in_libtonemap_displayMaxLuminance * 0.7;
                                        float y1 = maxOutLumi * 0.15;
                                        float x2 = in_libtonemap_displayMaxLuminance * 0.9;
                                        float y2 = maxOutLumi * 0.45;
                                        float x3 = in_libtonemap_displayMaxLuminance;
                                        float y3 = maxOutLumi;

                                        float c1 = y1 / 3.0;
                                        float c2 = y2 / 2.0;
                                        float c3 = y3 / 1.5;

                                        float nits = xyz.y;

                                        if (nits <= x0) {
                                            // scale [0.0, x0] to [0.0, y0] linearly
                                            float slope = y0 / x0;
                                            nits = nits * slope;
                                        } else if (nits <= x1) {
                                            // scale [x0, x1] to [y0, y1] using a curve
                                            float t = (nits - x0) / (x1 - x0);
                                            nits = (1.0 - t) * (1.0 - t) * y0 +
                                                    2.0 * (1.0 - t) * t * c1 + t * t * y1;
                                        } else if (nits <= x2) {
                                            // scale [x1, x2] to [y1, y2] using a curve
                                            float t = (nits - x1) / (x2 - x1);
                                            nits = (1.0 - t) * (1.0 - t) * y1 +
                                                    2.0 * (1.0 - t) * t * c2 + t * t * y2;
                                        } else {
                                            // scale [x2, x3] to [y2, y3] using a curve
                                            float t = (nits - x2) / (x3 - x2);
                                            nits = (1.0 - t) * (1.0 - t) * y2 +
                                                    2.0 * (1.0 - t) * t * c3 + t * t * y3;
                                        }

                                        return nits * libtonemap_applyBaseOOTFGain(nits);
                                    }
                                )");
                        break;
                    default:
                        // For completeness, this is tone-mapping from SDR to SDR, where this is
                        // just a no-op.
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(vec3 xyz) {
                                        return xyz.y;
                                    }
                                )");
                        break;
                }
                break;
        }

        program.append(R"(
            float libtonemap_LookupTonemapGain(vec3 linearRGB, vec3 xyz) {
                if (xyz.y <= 0.0) {
                    return 1.0;
                }
                return libtonemap_ToneMapTargetNits(xyz) / xyz.y;
            }
        )");
        return program;
    }

    std::vector<ShaderUniform> generateShaderSkSLUniforms(const Metadata& metadata) override {
        std::vector<ShaderUniform> uniforms;

        uniforms.reserve(2);

        uniforms.push_back({.name = "in_libtonemap_displayMaxLuminance",
                            .value = buildUniformValue<float>(metadata.displayMaxLuminance)});
        uniforms.push_back({.name = "in_libtonemap_inputMaxLuminance",
                            .value = buildUniformValue<float>(metadata.contentMaxLuminance)});
        return uniforms;
    }

    std::vector<Gain> lookupTonemapGain(
            aidl::android::hardware::graphics::common::Dataspace sourceDataspace,
            aidl::android::hardware::graphics::common::Dataspace destinationDataspace,
            const std::vector<Color>& colors, const Metadata& metadata) override {
        std::vector<Gain> gains;
        gains.reserve(colors.size());

        for (const auto [_, xyz] : colors) {
            if (xyz.y <= 0.0) {
                gains.push_back(1.0);
                continue;
            }
            const int32_t sourceDataspaceInt = static_cast<int32_t>(sourceDataspace);
            const int32_t destinationDataspaceInt = static_cast<int32_t>(destinationDataspace);

            double targetNits = 0.0;
            switch (sourceDataspaceInt & kTransferMask) {
                case kTransferST2084:
                case kTransferHLG:
                    switch (destinationDataspaceInt & kTransferMask) {
                        case kTransferST2084:
                            targetNits = xyz.y;
                            break;
                        case kTransferHLG:
                            // PQ has a wider luminance range (10,000 nits vs. 1,000 nits) than HLG,
                            // so we'll clamp the luminance range in case we're mapping from PQ
                            // input to HLG output.
                            targetNits = std::clamp(xyz.y, 0.0f, 1000.0f);
                            targetNits *= std::pow(targetNits / 1000.f, -0.2 / 1.2);
                            break;
                        default:
                            // Here we're mapping from HDR to SDR content, so interpolate using a
                            // Hermitian polynomial onto the smaller luminance range.

                            targetNits = xyz.y;

                            if ((sourceDataspaceInt & kTransferMask) == kTransferHLG) {
                                targetNits *= std::pow(targetNits, 0.2);
                            }
                            // if the max input luminance is less than what we can output then
                            // no tone mapping is needed as all color values will be in range.
                            if (metadata.contentMaxLuminance > metadata.displayMaxLuminance) {
                                // three control points
                                const double x0 = 10.0;
                                const double y0 = 17.0;
                                double x1 = metadata.displayMaxLuminance * 0.75;
                                double y1 = x1;
                                double x2 = x1 + (metadata.contentMaxLuminance - x1) / 2.0;
                                double y2 = y1 + (metadata.displayMaxLuminance - y1) * 0.75;

                                // horizontal distances between the last three control points
                                double h12 = x2 - x1;
                                double h23 = metadata.contentMaxLuminance - x2;
                                // tangents at the last three control points
                                double m1 = (y2 - y1) / h12;
                                double m3 = (metadata.displayMaxLuminance - y2) / h23;
                                double m2 = (m1 + m3) / 2.0;

                                if (targetNits < x0) {
                                    // scale [0.0, x0] to [0.0, y0] linearly
                                    double slope = y0 / x0;
                                    targetNits *= slope;
                                } else if (targetNits < x1) {
                                    // scale [x0, x1] to [y0, y1] linearly
                                    double slope = (y1 - y0) / (x1 - x0);
                                    targetNits = y0 + (targetNits - x0) * slope;
                                } else if (targetNits < x2) {
                                    // scale [x1, x2] to [y1, y2] using Hermite interp
                                    double t = (targetNits - x1) / h12;
                                    targetNits = (y1 * (1.0 + 2.0 * t) + h12 * m1 * t) * (1.0 - t) *
                                                    (1.0 - t) +
                                            (y2 * (3.0 - 2.0 * t) + h12 * m2 * (t - 1.0)) * t * t;
                                } else {
                                    // scale [x2, maxInLumi] to [y2, maxOutLumi] using Hermite
                                    // interp
                                    double t = (targetNits - x2) / h23;
                                    targetNits = (y2 * (1.0 + 2.0 * t) + h23 * m2 * t) * (1.0 - t) *
                                                    (1.0 - t) +
                                            (metadata.displayMaxLuminance * (3.0 - 2.0 * t) +
                                             h23 * m3 * (t - 1.0)) *
                                                    t * t;
                                }
                            }
                            break;
                    }
                    break;
                default:
                    // source is SDR
                    switch (destinationDataspaceInt & kTransferMask) {
                        case kTransferST2084:
                        case kTransferHLG: {
                            // Map from SDR onto an HDR output buffer
                            // Here we use a polynomial curve to map from [0, displayMaxLuminance]
                            // onto [0, maxOutLumi] which is hard-coded to be 3000 nits.
                            const double maxOutLumi = 3000.0;

                            double x0 = 5.0;
                            double y0 = 2.5;
                            double x1 = metadata.displayMaxLuminance * 0.7;
                            double y1 = maxOutLumi * 0.15;
                            double x2 = metadata.displayMaxLuminance * 0.9;
                            double y2 = maxOutLumi * 0.45;
                            double x3 = metadata.displayMaxLuminance;
                            double y3 = maxOutLumi;

                            double c1 = y1 / 3.0;
                            double c2 = y2 / 2.0;
                            double c3 = y3 / 1.5;

                            targetNits = xyz.y;

                            if (targetNits <= x0) {
                                // scale [0.0, x0] to [0.0, y0] linearly
                                double slope = y0 / x0;
                                targetNits *= slope;
                            } else if (targetNits <= x1) {
                                // scale [x0, x1] to [y0, y1] using a curve
                                double t = (targetNits - x0) / (x1 - x0);
                                targetNits = (1.0 - t) * (1.0 - t) * y0 + 2.0 * (1.0 - t) * t * c1 +
                                        t * t * y1;
                            } else if (targetNits <= x2) {
                                // scale [x1, x2] to [y1, y2] using a curve
                                double t = (targetNits - x1) / (x2 - x1);
                                targetNits = (1.0 - t) * (1.0 - t) * y1 + 2.0 * (1.0 - t) * t * c2 +
                                        t * t * y2;
                            } else {
                                // scale [x2, x3] to [y2, y3] using a curve
                                double t = (targetNits - x2) / (x3 - x2);
                                targetNits = (1.0 - t) * (1.0 - t) * y2 + 2.0 * (1.0 - t) * t * c3 +
                                        t * t * y3;
                            }

                            if ((destinationDataspaceInt & kTransferMask) == kTransferHLG) {
                                targetNits *= std::pow(targetNits / 1000.0, -0.2 / 1.2);
                            }
                        } break;
                        default:
                            // For completeness, this is tone-mapping from SDR to SDR, where this is
                            // just a no-op.
                            targetNits = xyz.y;
                            break;
                    }
            }
            gains.push_back(targetNits / xyz.y);
        }
        return gains;
    }
};

class ToneMapper13 : public ToneMapper {
private:
    double OETF_ST2084(double nits) {
        nits = nits / 10000.0;
        double m1 = (2610.0 / 4096.0) / 4.0;
        double m2 = (2523.0 / 4096.0) * 128.0;
        double c1 = (3424.0 / 4096.0);
        double c2 = (2413.0 / 4096.0) * 32.0;
        double c3 = (2392.0 / 4096.0) * 32.0;

        double tmp = std::pow(nits, m1);
        tmp = (c1 + c2 * tmp) / (1.0 + c3 * tmp);
        return std::pow(tmp, m2);
    }

    double OETF_HLG(double nits) {
        nits = nits / 1000.0;
        const double a = 0.17883277;
        const double b = 0.28466892;
        const double c = 0.55991073;
        return nits <= 1.0 / 12.0 ? std::sqrt(3.0 * nits) : a * std::log(12.0 * nits - b) + c;
    }

public:
    std::string generateTonemapGainShaderSkSL(
            aidl::android::hardware::graphics::common::Dataspace sourceDataspace,
            aidl::android::hardware::graphics::common::Dataspace destinationDataspace) override {
        const int32_t sourceDataspaceInt = static_cast<int32_t>(sourceDataspace);
        const int32_t destinationDataspaceInt = static_cast<int32_t>(destinationDataspace);

        std::string program;
        // Input uniforms
        program.append(R"(
                uniform float in_libtonemap_displayMaxLuminance;
                uniform float in_libtonemap_inputMaxLuminance;
                uniform float in_libtonemap_hlgGamma;
            )");
        switch (sourceDataspaceInt & kTransferMask) {
            case kTransferST2084:
                switch (destinationDataspaceInt & kTransferMask) {
                    case kTransferST2084:
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(float maxRGB) {
                                        return maxRGB;
                                    }
                                )");
                        break;
                    case kTransferHLG:
                        // PQ has a wider luminance range (10,000 nits vs. 1,000 nits) than HLG, so
                        // we'll clamp the luminance range in case we're mapping from PQ input to
                        // HLG output.
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(float maxRGB) {
                                        float nits = clamp(maxRGB, 0.0, 1000.0);
                                        float gamma = (1 - in_libtonemap_hlgGamma)
                                                / in_libtonemap_hlgGamma;
                                        return nits * pow(nits / 1000.0, gamma);
                                    }
                                )");
                        break;

                    default:
                        program.append(R"(
                                float libtonemap_OETFTone(float channel) {
                                    channel = channel / 10000.0;
                                    float m1 = (2610.0 / 4096.0) / 4.0;
                                    float m2 = (2523.0 / 4096.0) * 128.0;
                                    float c1 = (3424.0 / 4096.0);
                                    float c2 = (2413.0 / 4096.0) * 32.0;
                                    float c3 = (2392.0 / 4096.0) * 32.0;

                                    float tmp = pow(channel, float(m1));
                                    tmp = (c1 + c2 * tmp) / (1.0 + c3 * tmp);
                                    return pow(tmp, float(m2));
                                }

                                float libtonemap_ToneMapTargetNits(float maxRGB) {
                                    float maxInLumi = in_libtonemap_inputMaxLuminance;
                                    float maxOutLumi = in_libtonemap_displayMaxLuminance;

                                    float nits = maxRGB;

                                    float x1 = maxOutLumi * 0.65;
                                    float y1 = x1;

                                    float x3 = maxInLumi;
                                    float y3 = maxOutLumi;

                                    float x2 = x1 + (x3 - x1) * 4.0 / 17.0;
                                    float y2 = maxOutLumi * 0.9;

                                    float greyNorm1 = libtonemap_OETFTone(x1);
                                    float greyNorm2 = libtonemap_OETFTone(x2);
                                    float greyNorm3 = libtonemap_OETFTone(x3);

                                    float slope1 = 0;
                                    float slope2 = (y2 - y1) / (greyNorm2 - greyNorm1);
                                    float slope3 = (y3 - y2 ) / (greyNorm3 - greyNorm2);

                                    if (nits < x1) {
                                        return nits;
                                    }

                                    if (nits > maxInLumi) {
                                        return maxOutLumi;
                                    }

                                    float greyNits = libtonemap_OETFTone(nits);

                                    if (greyNits <= greyNorm2) {
                                        nits = (greyNits - greyNorm2) * slope2 + y2;
                                    } else if (greyNits <= greyNorm3) {
                                        nits = (greyNits - greyNorm3) * slope3 + y3;
                                    } else {
                                        nits = maxOutLumi;
                                    }

                                    return nits;
                                }
                                )");
                        break;
                }
                break;
            case kTransferHLG:
                switch (destinationDataspaceInt & kTransferMask) {
                    // HLG uses the OOTF from BT 2100.
                    case kTransferST2084:
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(float maxRGB) {
                                        return maxRGB
                                                * pow(maxRGB / 1000.0, in_libtonemap_hlgGamma - 1);
                                    }
                                )");
                        break;
                    case kTransferHLG:
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(float maxRGB) {
                                        return maxRGB;
                                    }
                                )");
                        break;
                    default:
                        // Follow BT 2100 and renormalize to max display luminance if we're
                        // tone-mapping down to SDR, as libshaders normalizes all SDR output from
                        // [0, maxDisplayLumins] -> [0, 1]
                        program.append(R"(
                                    float libtonemap_ToneMapTargetNits(float maxRGB) {
                                        return maxRGB
                                                * pow(maxRGB / 1000.0, in_libtonemap_hlgGamma - 1)
                                                * in_libtonemap_displayMaxLuminance / 1000.0;
                                    }
                                )");
                        break;
                }
                break;
            default:
                // Inverse tone-mapping and SDR-SDR mapping is not supported.
                program.append(R"(
                            float libtonemap_ToneMapTargetNits(float maxRGB) {
                                return maxRGB;
                            }
                        )");
                break;
        }

        program.append(R"(
            float libtonemap_LookupTonemapGain(vec3 linearRGB, vec3 xyz) {
                float maxRGB = max(linearRGB.r, max(linearRGB.g, linearRGB.b));
                if (maxRGB <= 0.0) {
                    return 1.0;
                }
                return libtonemap_ToneMapTargetNits(maxRGB) / maxRGB;
            }
        )");
        return program;
    }

    std::vector<ShaderUniform> generateShaderSkSLUniforms(const Metadata& metadata) override {
        // Hardcode the max content luminance to a "reasonable" level
        static const constexpr float kContentMaxLuminance = 4000.f;
        std::vector<ShaderUniform> uniforms;
        uniforms.reserve(3);
        uniforms.push_back({.name = "in_libtonemap_displayMaxLuminance",
                            .value = buildUniformValue<float>(metadata.displayMaxLuminance)});
        uniforms.push_back({.name = "in_libtonemap_inputMaxLuminance",
                            .value = buildUniformValue<float>(kContentMaxLuminance)});
        uniforms.push_back({.name = "in_libtonemap_hlgGamma",
                            .value = buildUniformValue<float>(
                                    computeHlgGamma(metadata.currentDisplayLuminance))});
        return uniforms;
    }

    std::vector<Gain> lookupTonemapGain(
            aidl::android::hardware::graphics::common::Dataspace sourceDataspace,
            aidl::android::hardware::graphics::common::Dataspace destinationDataspace,
            const std::vector<Color>& colors, const Metadata& metadata) override {
        std::vector<Gain> gains;
        gains.reserve(colors.size());

        // Precompute constants for HDR->SDR tonemapping parameters
        constexpr double maxInLumi = 4000;
        const double maxOutLumi = metadata.displayMaxLuminance;

        const double x1 = maxOutLumi * 0.65;
        const double y1 = x1;

        const double x3 = maxInLumi;
        const double y3 = maxOutLumi;

        const double x2 = x1 + (x3 - x1) * 4.0 / 17.0;
        const double y2 = maxOutLumi * 0.9;

        const double greyNorm1 = OETF_ST2084(x1);
        const double greyNorm2 = OETF_ST2084(x2);
        const double greyNorm3 = OETF_ST2084(x3);

        const double slope2 = (y2 - y1) / (greyNorm2 - greyNorm1);
        const double slope3 = (y3 - y2) / (greyNorm3 - greyNorm2);

        const double hlgGamma = computeHlgGamma(metadata.currentDisplayLuminance);

        for (const auto [linearRGB, _] : colors) {
            double maxRGB = std::max({linearRGB.r, linearRGB.g, linearRGB.b});

            if (maxRGB <= 0.0) {
                gains.push_back(1.0);
                continue;
            }

            const int32_t sourceDataspaceInt = static_cast<int32_t>(sourceDataspace);
            const int32_t destinationDataspaceInt = static_cast<int32_t>(destinationDataspace);

            double targetNits = 0.0;
            switch (sourceDataspaceInt & kTransferMask) {
                case kTransferST2084:
                    switch (destinationDataspaceInt & kTransferMask) {
                        case kTransferST2084:
                            targetNits = maxRGB;
                            break;
                        case kTransferHLG:
                            // PQ has a wider luminance range (10,000 nits vs. 1,000 nits) than HLG,
                            // so we'll clamp the luminance range in case we're mapping from PQ
                            // input to HLG output.
                            targetNits = std::clamp(maxRGB, 0.0, 1000.0);
                            targetNits *= pow(targetNits / 1000.0, (1 - hlgGamma) / (hlgGamma));
                            break;
                        default:
                            targetNits = maxRGB;
                            if (targetNits < x1) {
                                break;
                            }

                            if (targetNits > maxInLumi) {
                                targetNits = maxOutLumi;
                                break;
                            }

                            const double greyNits = OETF_ST2084(targetNits);

                            if (greyNits <= greyNorm2) {
                                targetNits = (greyNits - greyNorm2) * slope2 + y2;
                            } else if (greyNits <= greyNorm3) {
                                targetNits = (greyNits - greyNorm3) * slope3 + y3;
                            } else {
                                targetNits = maxOutLumi;
                            }
                            break;
                    }
                    break;
                case kTransferHLG:
                    switch (destinationDataspaceInt & kTransferMask) {
                        case kTransferST2084:
                            targetNits = maxRGB * pow(maxRGB / 1000.0, hlgGamma - 1);
                            break;
                        case kTransferHLG:
                            targetNits = maxRGB;
                            break;
                        default:
                            targetNits = maxRGB * pow(maxRGB / 1000.0, hlgGamma - 1) *
                                    metadata.displayMaxLuminance / 1000.0;
                            break;
                    }
                    break;
                default:
                    targetNits = maxRGB;
                    break;
            }

            gains.push_back(targetNits / maxRGB);
        }
        return gains;
    }
};

} // namespace

ToneMapper* getToneMapper() {
    static std::once_flag sOnce;
    static std::unique_ptr<ToneMapper> sToneMapper;

    std::call_once(sOnce, [&] {
        switch (kToneMapAlgorithm) {
            case ToneMapAlgorithm::AndroidO:
                sToneMapper = std::unique_ptr<ToneMapper>(new ToneMapperO());
                break;
            case ToneMapAlgorithm::Android13:
                sToneMapper = std::unique_ptr<ToneMapper>(new ToneMapper13());
        }
    });

    return sToneMapper.get();
}
} // namespace android::tonemap
