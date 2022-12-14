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

#include <shaders/shaders.h>

#include <tonemap/tonemap.h>

#include <cmath>
#include <optional>

#include <math/mat4.h>
#include <system/graphics-base-v1.0.h>
#include <ui/ColorSpace.h>

namespace android::shaders {

namespace {

aidl::android::hardware::graphics::common::Dataspace toAidlDataspace(ui::Dataspace dataspace) {
    return static_cast<aidl::android::hardware::graphics::common::Dataspace>(dataspace);
}

void generateEOTF(ui::Dataspace dataspace, std::string& shader) {
    switch (dataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_ST2084:
            shader.append(R"(

                float3 EOTF(float3 color) {
                    float m1 = (2610.0 / 4096.0) / 4.0;
                    float m2 = (2523.0 / 4096.0) * 128.0;
                    float c1 = (3424.0 / 4096.0);
                    float c2 = (2413.0 / 4096.0) * 32.0;
                    float c3 = (2392.0 / 4096.0) * 32.0;

                    float3 tmp = pow(clamp(color, 0.0, 1.0), 1.0 / float3(m2));
                    tmp = max(tmp - c1, 0.0) / (c2 - c3 * tmp);
                    return pow(tmp, 1.0 / float3(m1));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_HLG:
            shader.append(R"(
                float EOTF_channel(float channel) {
                    const float a = 0.17883277;
                    const float b = 0.28466892;
                    const float c = 0.55991073;
                    return channel <= 0.5 ? channel * channel / 3.0 :
                            (exp((channel - c) / a) + b) / 12.0;
                }

                float3 EOTF(float3 color) {
                    return float3(EOTF_channel(color.r), EOTF_channel(color.g),
                            EOTF_channel(color.b));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_LINEAR:
            shader.append(R"(
                float3 EOTF(float3 color) {
                    return color;
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_SMPTE_170M:
            shader.append(R"(

                float EOTF_sRGB(float srgb) {
                    return srgb <= 0.08125 ? srgb / 4.50 : pow((srgb + 0.099) / 1.099, 1 / 0.45);
                }

                float3 EOTF_sRGB(float3 srgb) {
                    return float3(EOTF_sRGB(srgb.r), EOTF_sRGB(srgb.g), EOTF_sRGB(srgb.b));
                }

                float3 EOTF(float3 srgb) {
                    return sign(srgb.rgb) * EOTF_sRGB(abs(srgb.rgb));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_GAMMA2_2:
            shader.append(R"(

                float EOTF_sRGB(float srgb) {
                    return pow(srgb, 2.2);
                }

                float3 EOTF_sRGB(float3 srgb) {
                    return float3(EOTF_sRGB(srgb.r), EOTF_sRGB(srgb.g), EOTF_sRGB(srgb.b));
                }

                float3 EOTF(float3 srgb) {
                    return sign(srgb.rgb) * EOTF_sRGB(abs(srgb.rgb));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_GAMMA2_6:
            shader.append(R"(

                float EOTF_sRGB(float srgb) {
                    return pow(srgb, 2.6);
                }

                float3 EOTF_sRGB(float3 srgb) {
                    return float3(EOTF_sRGB(srgb.r), EOTF_sRGB(srgb.g), EOTF_sRGB(srgb.b));
                }

                float3 EOTF(float3 srgb) {
                    return sign(srgb.rgb) * EOTF_sRGB(abs(srgb.rgb));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_GAMMA2_8:
            shader.append(R"(

                float EOTF_sRGB(float srgb) {
                    return pow(srgb, 2.8);
                }

                float3 EOTF_sRGB(float3 srgb) {
                    return float3(EOTF_sRGB(srgb.r), EOTF_sRGB(srgb.g), EOTF_sRGB(srgb.b));
                }

                float3 EOTF(float3 srgb) {
                    return sign(srgb.rgb) * EOTF_sRGB(abs(srgb.rgb));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_SRGB:
        default:
            shader.append(R"(

                float EOTF_sRGB(float srgb) {
                    return srgb <= 0.04045 ? srgb / 12.92 : pow((srgb + 0.055) / 1.055, 2.4);
                }

                float3 EOTF_sRGB(float3 srgb) {
                    return float3(EOTF_sRGB(srgb.r), EOTF_sRGB(srgb.g), EOTF_sRGB(srgb.b));
                }

                float3 EOTF(float3 srgb) {
                    return sign(srgb.rgb) * EOTF_sRGB(abs(srgb.rgb));
                }
            )");
            break;
    }
}

void generateXYZTransforms(std::string& shader) {
    shader.append(R"(
        uniform float4x4 in_rgbToXyz;
        uniform float4x4 in_xyzToRgb;
        float3 ToXYZ(float3 rgb) {
            return (in_rgbToXyz * float4(rgb, 1.0)).rgb;
        }

        float3 ToRGB(float3 xyz) {
            return clamp((in_xyzToRgb * float4(xyz, 1.0)).rgb, 0.0, 1.0);
        }
    )");
}

// Conversion from relative light to absolute light (maps from [0, 1] to [0, maxNits])
void generateLuminanceScalesForOOTF(ui::Dataspace inputDataspace, ui::Dataspace outputDataspace,
                                    std::string& shader) {
    switch (inputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_ST2084:
            shader.append(R"(
                    float3 ScaleLuminance(float3 xyz) {
                        return xyz * 10000.0;
                    }
                )");
            break;
        case HAL_DATASPACE_TRANSFER_HLG:
            shader.append(R"(
                    float3 ScaleLuminance(float3 xyz) {
                        return xyz * 1000.0;
                    }
                )");
            break;
        default:
            switch (outputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
                case HAL_DATASPACE_TRANSFER_ST2084:
                case HAL_DATASPACE_TRANSFER_HLG:
                    // SDR -> HDR tonemap
                    shader.append(R"(
                            float3 ScaleLuminance(float3 xyz) {
                                return xyz * in_libtonemap_inputMaxLuminance;
                            }
                        )");
                    break;
                default:
                    // Input and output are both SDR, so no tone-mapping is expected so
                    // no-op the luminance normalization.
                    shader.append(R"(
                                float3 ScaleLuminance(float3 xyz) {
                                    return xyz * in_libtonemap_displayMaxLuminance;
                                }
                            )");
                    break;
            }
    }
}

// Normalizes from absolute light back to relative light (maps from [0, maxNits] back to [0, 1])
static void generateLuminanceNormalizationForOOTF(ui::Dataspace outputDataspace,
                                                  std::string& shader) {
    switch (outputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_ST2084:
            shader.append(R"(
                    float3 NormalizeLuminance(float3 xyz) {
                        return xyz / 10000.0;
                    }
                )");
            break;
        case HAL_DATASPACE_TRANSFER_HLG:
            shader.append(R"(
                    float3 NormalizeLuminance(float3 xyz) {
                        return xyz / 1000.0;
                    }
                )");
            break;
        default:
            shader.append(R"(
                    float3 NormalizeLuminance(float3 xyz) {
                        return xyz / in_libtonemap_displayMaxLuminance;
                    }
                )");
            break;
    }
}

void generateOOTF(ui::Dataspace inputDataspace, ui::Dataspace outputDataspace,
                  std::string& shader) {
    shader.append(tonemap::getToneMapper()
                          ->generateTonemapGainShaderSkSL(toAidlDataspace(inputDataspace),
                                                          toAidlDataspace(outputDataspace))
                          .c_str());

    generateLuminanceScalesForOOTF(inputDataspace, outputDataspace, shader);
    generateLuminanceNormalizationForOOTF(outputDataspace, shader);

    shader.append(R"(
            float3 OOTF(float3 linearRGB, float3 xyz) {
                float3 scaledLinearRGB = ScaleLuminance(linearRGB);
                float3 scaledXYZ = ScaleLuminance(xyz);

                float gain = libtonemap_LookupTonemapGain(scaledLinearRGB, scaledXYZ);

                return NormalizeLuminance(scaledXYZ * gain);
            }
        )");
}

void generateOETF(ui::Dataspace dataspace, std::string& shader) {
    switch (dataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_ST2084:
            shader.append(R"(

                float3 OETF(float3 xyz) {
                    float m1 = (2610.0 / 4096.0) / 4.0;
                    float m2 = (2523.0 / 4096.0) * 128.0;
                    float c1 = (3424.0 / 4096.0);
                    float c2 = (2413.0 / 4096.0) * 32.0;
                    float c3 = (2392.0 / 4096.0) * 32.0;

                    float3 tmp = pow(xyz, float3(m1));
                    tmp = (c1 + c2 * tmp) / (1.0 + c3 * tmp);
                    return pow(tmp, float3(m2));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_HLG:
            shader.append(R"(
                float OETF_channel(float channel) {
                    const float a = 0.17883277;
                    const float b = 0.28466892;
                    const float c = 0.55991073;
                    return channel <= 1.0 / 12.0 ? sqrt(3.0 * channel) :
                            a * log(12.0 * channel - b) + c;
                }

                float3 OETF(float3 linear) {
                    return float3(OETF_channel(linear.r), OETF_channel(linear.g),
                            OETF_channel(linear.b));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_LINEAR:
            shader.append(R"(
                float3 OETF(float3 linear) {
                    return linear;
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_SMPTE_170M:
            shader.append(R"(
                float OETF_sRGB(float linear) {
                    return linear <= 0.018 ?
                            linear * 4.50 : (pow(linear, 0.45) * 1.099) - 0.099;
                }

                float3 OETF_sRGB(float3 linear) {
                    return float3(OETF_sRGB(linear.r), OETF_sRGB(linear.g), OETF_sRGB(linear.b));
                }

                float3 OETF(float3 linear) {
                    return sign(linear.rgb) * OETF_sRGB(abs(linear.rgb));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_GAMMA2_2:
            shader.append(R"(
                float OETF_sRGB(float linear) {
                    return pow(linear, (1.0 / 2.2));
                }

                float3 OETF_sRGB(float3 linear) {
                    return float3(OETF_sRGB(linear.r), OETF_sRGB(linear.g), OETF_sRGB(linear.b));
                }

                float3 OETF(float3 linear) {
                    return sign(linear.rgb) * OETF_sRGB(abs(linear.rgb));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_GAMMA2_6:
            shader.append(R"(
                float OETF_sRGB(float linear) {
                    return pow(linear, (1.0 / 2.6));
                }

                float3 OETF_sRGB(float3 linear) {
                    return float3(OETF_sRGB(linear.r), OETF_sRGB(linear.g), OETF_sRGB(linear.b));
                }

                float3 OETF(float3 linear) {
                    return sign(linear.rgb) * OETF_sRGB(abs(linear.rgb));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_GAMMA2_8:
            shader.append(R"(
                float OETF_sRGB(float linear) {
                    return pow(linear, (1.0 / 2.8));
                }

                float3 OETF_sRGB(float3 linear) {
                    return float3(OETF_sRGB(linear.r), OETF_sRGB(linear.g), OETF_sRGB(linear.b));
                }

                float3 OETF(float3 linear) {
                    return sign(linear.rgb) * OETF_sRGB(abs(linear.rgb));
                }
            )");
            break;
        case HAL_DATASPACE_TRANSFER_SRGB:
        default:
            shader.append(R"(
                float OETF_sRGB(float linear) {
                    return linear <= 0.0031308 ?
                            linear * 12.92 : (pow(linear, 1.0 / 2.4) * 1.055) - 0.055;
                }

                float3 OETF_sRGB(float3 linear) {
                    return float3(OETF_sRGB(linear.r), OETF_sRGB(linear.g), OETF_sRGB(linear.b));
                }

                float3 OETF(float3 linear) {
                    return sign(linear.rgb) * OETF_sRGB(abs(linear.rgb));
                }
            )");
            break;
    }
}

void generateEffectiveOOTF(bool undoPremultipliedAlpha, std::string& shader) {
    shader.append(R"(
        uniform shader child;
        half4 main(float2 xy) {
            float4 c = float4(child.eval(xy));
    )");
    if (undoPremultipliedAlpha) {
        shader.append(R"(
            c.rgb = c.rgb / (c.a + 0.0019);
        )");
    }
    shader.append(R"(
        float3 linearRGB = EOTF(c.rgb);
        float3 xyz = ToXYZ(linearRGB);
        c.rgb = OETF(ToRGB(OOTF(linearRGB, xyz)));
    )");
    if (undoPremultipliedAlpha) {
        shader.append(R"(
            c.rgb = c.rgb * (c.a + 0.0019);
        )");
    }
    shader.append(R"(
            return c;
        }
    )");
}

// please keep in sync with toSkColorSpace function in renderengine/skia/ColorSpaces.cpp
ColorSpace toColorSpace(ui::Dataspace dataspace) {
    switch (dataspace & HAL_DATASPACE_STANDARD_MASK) {
        case HAL_DATASPACE_STANDARD_BT709:
            return ColorSpace::sRGB();
        case HAL_DATASPACE_STANDARD_DCI_P3:
            return ColorSpace::DisplayP3();
        case HAL_DATASPACE_STANDARD_BT2020:
        case HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE:
            return ColorSpace::BT2020();
        case HAL_DATASPACE_STANDARD_ADOBE_RGB:
            return ColorSpace::AdobeRGB();
        // TODO(b/208290320): BT601 format and variants return different primaries
        case HAL_DATASPACE_STANDARD_BT601_625:
        case HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED:
        case HAL_DATASPACE_STANDARD_BT601_525:
        case HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED:
        // TODO(b/208290329): BT407M format returns different primaries
        case HAL_DATASPACE_STANDARD_BT470M:
        // TODO(b/208290904): FILM format returns different primaries
        case HAL_DATASPACE_STANDARD_FILM:
        case HAL_DATASPACE_STANDARD_UNSPECIFIED:
        default:
            return ColorSpace::sRGB();
    }
}

template <typename T, std::enable_if_t<std::is_trivially_copyable<T>::value, bool> = true>
std::vector<uint8_t> buildUniformValue(T value) {
    std::vector<uint8_t> result;
    result.resize(sizeof(value));
    std::memcpy(result.data(), &value, sizeof(value));
    return result;
}

} // namespace

std::string buildLinearEffectSkSL(const LinearEffect& linearEffect) {
    std::string shaderString;
    generateEOTF(linearEffect.fakeInputDataspace == ui::Dataspace::UNKNOWN
                         ? linearEffect.inputDataspace
                         : linearEffect.fakeInputDataspace,
                 shaderString);
    generateXYZTransforms(shaderString);
    generateOOTF(linearEffect.inputDataspace, linearEffect.outputDataspace, shaderString);
    generateOETF(linearEffect.outputDataspace, shaderString);
    generateEffectiveOOTF(linearEffect.undoPremultipliedAlpha, shaderString);
    return shaderString;
}

// Generates a list of uniforms to set on the LinearEffect shader above.
std::vector<tonemap::ShaderUniform> buildLinearEffectUniforms(
        const LinearEffect& linearEffect, const mat4& colorTransform, float maxDisplayLuminance,
        float currentDisplayLuminanceNits, float maxLuminance, AHardwareBuffer* buffer,
        aidl::android::hardware::graphics::composer3::RenderIntent renderIntent) {
    std::vector<tonemap::ShaderUniform> uniforms;

    const ui::Dataspace inputDataspace = linearEffect.fakeInputDataspace == ui::Dataspace::UNKNOWN
            ? linearEffect.inputDataspace
            : linearEffect.fakeInputDataspace;

    if (inputDataspace == linearEffect.outputDataspace) {
        uniforms.push_back({.name = "in_rgbToXyz", .value = buildUniformValue<mat4>(mat4())});
        uniforms.push_back(
                {.name = "in_xyzToRgb", .value = buildUniformValue<mat4>(colorTransform)});
    } else {
        ColorSpace inputColorSpace = toColorSpace(inputDataspace);
        ColorSpace outputColorSpace = toColorSpace(linearEffect.outputDataspace);
        uniforms.push_back({.name = "in_rgbToXyz",
                            .value = buildUniformValue<mat4>(mat4(inputColorSpace.getRGBtoXYZ()))});
        uniforms.push_back({.name = "in_xyzToRgb",
                            .value = buildUniformValue<mat4>(
                                    colorTransform * mat4(outputColorSpace.getXYZtoRGB()))});
    }

    tonemap::Metadata metadata{.displayMaxLuminance = maxDisplayLuminance,
                               // If the input luminance is unknown, use display luminance (aka,
                               // no-op any luminance changes)
                               // This will be the case for eg screenshots in addition to
                               // uncalibrated displays
                               .contentMaxLuminance =
                                       maxLuminance > 0 ? maxLuminance : maxDisplayLuminance,
                               .currentDisplayLuminance = currentDisplayLuminanceNits > 0
                                       ? currentDisplayLuminanceNits
                                       : maxDisplayLuminance,
                               .buffer = buffer,
                               .renderIntent = renderIntent};

    for (const auto uniform : tonemap::getToneMapper()->generateShaderSkSLUniforms(metadata)) {
        uniforms.push_back(uniform);
    }

    return uniforms;
}

} // namespace android::shaders
