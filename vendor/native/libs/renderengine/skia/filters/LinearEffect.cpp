/*
 * Copyright 2020 The Android Open Source Project
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

#include "LinearEffect.h"

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <SkString.h>
#include <utils/Trace.h>

#include <optional>

#include "log/log.h"
#include "math/mat4.h"
#include "system/graphics-base-v1.0.h"
#include "ui/ColorSpace.h"

namespace android {
namespace renderengine {
namespace skia {

static void generateEOTF(ui::Dataspace dataspace, SkString& shader) {
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

static void generateXYZTransforms(SkString& shader) {
    shader.append(R"(
        uniform float4x4 in_rgbToXyz;
        uniform float4x4 in_xyzToRgb;
        float3 ToXYZ(float3 rgb) {
            return clamp((in_rgbToXyz * float4(rgb, 1.0)).rgb, 0.0, 1.0);
        }

        float3 ToRGB(float3 xyz) {
            return clamp((in_xyzToRgb * float4(xyz, 1.0)).rgb, 0.0, 1.0);
        }
    )");
}

// Conversion from relative light to absolute light (maps from [0, 1] to [0, maxNits])
static void generateLuminanceScalesForOOTF(ui::Dataspace inputDataspace, SkString& shader) {
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
                        return xyz * 1000.0 * pow(xyz.y, 0.2);
                    }
                )");
            break;
        default:
            shader.append(R"(
                    float3 ScaleLuminance(float3 xyz) {
                        return xyz * in_inputMaxLuminance;
                    }
                )");
            break;
    }
}

static void generateToneMapInterpolation(ui::Dataspace inputDataspace,
                                         ui::Dataspace outputDataspace, SkString& shader) {
    switch (inputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_ST2084:
        case HAL_DATASPACE_TRANSFER_HLG:
            switch (outputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
                case HAL_DATASPACE_TRANSFER_ST2084:
                    shader.append(R"(
                            float3 ToneMap(float3 xyz) {
                                return xyz;
                            }
                        )");
                    break;
                case HAL_DATASPACE_TRANSFER_HLG:
                    // PQ has a wider luminance range (10,000 nits vs. 1,000 nits) than HLG, so
                    // we'll clamp the luminance range in case we're mapping from PQ input to HLG
                    // output.
                    shader.append(R"(
                            float3 ToneMap(float3 xyz) {
                                return clamp(xyz, 0.0, 1000.0);
                            }
                        )");
                    break;
                default:
                    // Here we're mapping from HDR to SDR content, so interpolate using a Hermitian
                    // polynomial onto the smaller luminance range.
                    shader.append(R"(
                            float3 ToneMap(float3 xyz) {
                                float maxInLumi = in_inputMaxLuminance;
                                float maxOutLumi = in_displayMaxLuminance;

                                float nits = xyz.y;

                                // if the max input luminance is less than what we can output then
                                // no tone mapping is needed as all color values will be in range.
                                if (maxInLumi <= maxOutLumi) {
                                    return xyz;
                                } else {

                                    // three control points
                                    const float x0 = 10.0;
                                    const float y0 = 17.0;
                                    float x1 = maxOutLumi * 0.75;
                                    float y1 = x1;
                                    float x2 = x1 + (maxInLumi - x1) / 2.0;
                                    float y2 = y1 + (maxOutLumi - y1) * 0.75;

                                    // horizontal distances between the last three control points
                                    float h12 = x2 - x1;
                                    float h23 = maxInLumi - x2;
                                    // tangents at the last three control points
                                    float m1 = (y2 - y1) / h12;
                                    float m3 = (maxOutLumi - y2) / h23;
                                    float m2 = (m1 + m3) / 2.0;

                                    if (nits < x0) {
                                        // scale [0.0, x0] to [0.0, y0] linearly
                                        float slope = y0 / x0;
                                        return xyz * slope;
                                    } else if (nits < x1) {
                                        // scale [x0, x1] to [y0, y1] linearly
                                        float slope = (y1 - y0) / (x1 - x0);
                                        nits = y0 + (nits - x0) * slope;
                                    } else if (nits < x2) {
                                        // scale [x1, x2] to [y1, y2] using Hermite interp
                                        float t = (nits - x1) / h12;
                                        nits = (y1 * (1.0 + 2.0 * t) + h12 * m1 * t) * (1.0 - t) * (1.0 - t) +
                                                (y2 * (3.0 - 2.0 * t) + h12 * m2 * (t - 1.0)) * t * t;
                                    } else {
                                        // scale [x2, maxInLumi] to [y2, maxOutLumi] using Hermite interp
                                        float t = (nits - x2) / h23;
                                        nits = (y2 * (1.0 + 2.0 * t) + h23 * m2 * t) * (1.0 - t) * (1.0 - t) +
                                                (maxOutLumi * (3.0 - 2.0 * t) + h23 * m3 * (t - 1.0)) * t * t;
                                    }
                                }

                                // color.y is greater than x0 and is thus non-zero
                                return xyz * (nits / xyz.y);
                            }
                        )");
                    break;
            }
            break;
        default:
            switch (outputDataspace & HAL_DATASPACE_TRANSFER_MASK) {
                case HAL_DATASPACE_TRANSFER_ST2084:
                case HAL_DATASPACE_TRANSFER_HLG:
                    // Map from SDR onto an HDR output buffer
                    // Here we use a polynomial curve to map from [0, displayMaxLuminance] onto
                    // [0, maxOutLumi] which is hard-coded to be 3000 nits.
                    shader.append(R"(
                            float3 ToneMap(float3 xyz) {
                                const float maxOutLumi = 3000.0;

                                const float x0 = 5.0;
                                const float y0 = 2.5;
                                float x1 = in_displayMaxLuminance * 0.7;
                                float y1 = maxOutLumi * 0.15;
                                float x2 = in_displayMaxLuminance * 0.9;
                                float y2 = maxOutLumi * 0.45;
                                float x3 = in_displayMaxLuminance;
                                float y3 = maxOutLumi;

                                float c1 = y1 / 3.0;
                                float c2 = y2 / 2.0;
                                float c3 = y3 / 1.5;

                                float nits = xyz.y;

                                if (nits <= x0) {
                                    // scale [0.0, x0] to [0.0, y0] linearly
                                    float slope = y0 / x0;
                                    return xyz * slope;
                                } else if (nits <= x1) {
                                    // scale [x0, x1] to [y0, y1] using a curve
                                    float t = (nits - x0) / (x1 - x0);
                                    nits = (1.0 - t) * (1.0 - t) * y0 + 2.0 * (1.0 - t) * t * c1 + t * t * y1;
                                } else if (nits <= x2) {
                                    // scale [x1, x2] to [y1, y2] using a curve
                                    float t = (nits - x1) / (x2 - x1);
                                    nits = (1.0 - t) * (1.0 - t) * y1 + 2.0 * (1.0 - t) * t * c2 + t * t * y2;
                                } else {
                                    // scale [x2, x3] to [y2, y3] using a curve
                                    float t = (nits - x2) / (x3 - x2);
                                    nits = (1.0 - t) * (1.0 - t) * y2 + 2.0 * (1.0 - t) * t * c3 + t * t * y3;
                                }

                                // xyz.y is greater than x0 and is thus non-zero
                                return xyz * (nits / xyz.y);
                            }
                        )");
                    break;
                default:
                    // For completeness, this is tone-mapping from SDR to SDR, where this is just a
                    // no-op.
                    shader.append(R"(
                            float3 ToneMap(float3 xyz) {
                                return xyz;
                            }
                        )");
                    break;
            }
            break;
    }
}

// Normalizes from absolute light back to relative light (maps from [0, maxNits] back to [0, 1])
static void generateLuminanceNormalizationForOOTF(ui::Dataspace outputDataspace, SkString& shader) {
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
                        return xyz / 1000.0 * pow(xyz.y / 1000.0, -0.2 / 1.2);
                    }
                )");
            break;
        default:
            shader.append(R"(
                    float3 NormalizeLuminance(float3 xyz) {
                        return xyz / in_displayMaxLuminance;
                    }
                )");
            break;
    }
}

static void generateOOTF(ui::Dataspace inputDataspace, ui::Dataspace outputDataspace,
                         SkString& shader) {
    // Input uniforms
    shader.append(R"(
            uniform float in_displayMaxLuminance;
            uniform float in_inputMaxLuminance;
        )");

    generateLuminanceScalesForOOTF(inputDataspace, shader);
    generateToneMapInterpolation(inputDataspace, outputDataspace, shader);
    generateLuminanceNormalizationForOOTF(outputDataspace, shader);

    shader.append(R"(
            float3 OOTF(float3 xyz) {
                return NormalizeLuminance(ToneMap(ScaleLuminance(xyz)));
            }
        )");
}

static void generateOETF(ui::Dataspace dataspace, SkString& shader) {
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

static void generateEffectiveOOTF(bool undoPremultipliedAlpha, SkString& shader) {
    shader.append(R"(
        uniform shader input;
        half4 main(float2 xy) {
            float4 c = float4(sample(input, xy));
    )");
    if (undoPremultipliedAlpha) {
        shader.append(R"(
            c.rgb = c.rgb / (c.a + 0.0019);
        )");
    }
    shader.append(R"(
        c.rgb = OETF(ToRGB(OOTF(ToXYZ(EOTF(c.rgb)))));
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
static ColorSpace toColorSpace(ui::Dataspace dataspace) {
    switch (dataspace & HAL_DATASPACE_STANDARD_MASK) {
        case HAL_DATASPACE_STANDARD_BT709:
            return ColorSpace::sRGB();
            break;
        case HAL_DATASPACE_STANDARD_DCI_P3:
            return ColorSpace::DisplayP3();
            break;
        case HAL_DATASPACE_STANDARD_BT2020:
            return ColorSpace::BT2020();
            break;
        default:
            return ColorSpace::sRGB();
            break;
    }
}

sk_sp<SkRuntimeEffect> buildRuntimeEffect(const LinearEffect& linearEffect) {
    ATRACE_CALL();
    SkString shaderString;
    generateEOTF(linearEffect.inputDataspace, shaderString);
    generateXYZTransforms(shaderString);
    generateOOTF(linearEffect.inputDataspace, linearEffect.outputDataspace, shaderString);
    generateOETF(linearEffect.outputDataspace, shaderString);
    generateEffectiveOOTF(linearEffect.undoPremultipliedAlpha, shaderString);

    auto [shader, error] = SkRuntimeEffect::MakeForShader(shaderString);
    if (!shader) {
        LOG_ALWAYS_FATAL("LinearColorFilter construction error: %s", error.c_str());
    }
    return shader;
}

sk_sp<SkShader> createLinearEffectShader(sk_sp<SkShader> shader, const LinearEffect& linearEffect,
                                         sk_sp<SkRuntimeEffect> runtimeEffect,
                                         const mat4& colorTransform, float maxDisplayLuminance,
                                         float maxLuminance) {
    ATRACE_CALL();
    SkRuntimeShaderBuilder effectBuilder(runtimeEffect);

    effectBuilder.child("input") = shader;

    if (linearEffect.inputDataspace == linearEffect.outputDataspace) {
        effectBuilder.uniform("in_rgbToXyz") = mat4();
        effectBuilder.uniform("in_xyzToRgb") = colorTransform;
    } else {
        ColorSpace inputColorSpace = toColorSpace(linearEffect.inputDataspace);
        ColorSpace outputColorSpace = toColorSpace(linearEffect.outputDataspace);

        effectBuilder.uniform("in_rgbToXyz") = mat4(inputColorSpace.getRGBtoXYZ());
        effectBuilder.uniform("in_xyzToRgb") =
                colorTransform * mat4(outputColorSpace.getXYZtoRGB());
    }

    effectBuilder.uniform("in_displayMaxLuminance") = maxDisplayLuminance;
    // If the input luminance is unknown, use display luminance (aka, no-op any luminance changes)
    // This will be the case for eg screenshots in addition to uncalibrated displays
    effectBuilder.uniform("in_inputMaxLuminance") =
            maxLuminance > 0 ? maxLuminance : maxDisplayLuminance;
    return effectBuilder.makeShader(nullptr, false);
}

} // namespace skia
} // namespace renderengine
} // namespace android