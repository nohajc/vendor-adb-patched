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
#include "Cache.h"
#include "AutoBackendTexture.h"
#include "SkiaRenderEngine.h"
#include "android-base/unique_fd.h"
#include "renderengine/DisplaySettings.h"
#include "renderengine/LayerSettings.h"
#include "renderengine/impl/ExternalTexture.h"
#include "ui/GraphicBuffer.h"
#include "ui/GraphicTypes.h"
#include "ui/PixelFormat.h"
#include "ui/Rect.h"
#include "utils/Timers.h"

namespace android::renderengine::skia {

namespace {
// Warming shader cache, not framebuffer cache.
constexpr bool kUseFrameBufferCache = false;

// clang-format off
// Any non-identity matrix will do.
const auto kScaleAndTranslate = mat4(0.7f,   0.f, 0.f, 0.f,
                                     0.f,  0.7f, 0.f, 0.f,
                                     0.f,   0.f, 1.f, 0.f,
                                   67.3f, 52.2f, 0.f, 1.f);
const auto kScaleAsymmetric = mat4(0.8f, 0.f,  0.f, 0.f,
                                   0.f,  1.1f, 0.f, 0.f,
                                   0.f,  0.f,  1.f, 0.f,
                                   0.f,  0.f,  0.f, 1.f);
const auto kFlip = mat4(1.1f, -0.1f,  0.f, 0.f,
                        0.1f,  1.1f,  0.f, 0.f,
                        0.f,    0.f,  1.f, 0.f,
                        2.f,    2.f,  0.f, 1.f);
// clang-format on
// When setting layer.sourceDataspace, whether it matches the destination or not determines whether
// a color correction effect is added to the shader.
constexpr auto kDestDataSpace = ui::Dataspace::SRGB;
constexpr auto kOtherDataSpace = ui::Dataspace::DISPLAY_P3;
} // namespace

static void drawShadowLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                             const std::shared_ptr<ExternalTexture>& dstTexture) {
    // Somewhat arbitrary dimensions, but on screen and slightly shorter, based
    // on actual use.
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    FloatRect smallerRect(20, 20, displayRect.width()-20, displayRect.height()-20);

    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                            .roundedCornersCrop = rect,
                            .roundedCornersRadius = {50.f, 50.f},
                    },
            // drawShadow ignores alpha
            .shadow =
                    ShadowSettings{
                            .boundaries = rect,
                            .ambientColor = vec4(0, 0, 0, 0.00935997f),
                            .spotColor = vec4(0, 0, 0, 0.0455841f),
                            .lightPos = vec3(500.f, -1500.f, 1500.f),
                            .lightRadius = 2500.0f,
                            .length = 15.f,
                    },
            // setting this is mandatory for shadows and blurs
            .skipContentDraw = true,
            .alpha = 1,
    };
    LayerSettings caster{
            .geometry =
                    Geometry{
                            .boundaries = smallerRect,
                            .roundedCornersCrop = rect,
                            .roundedCornersRadius = {50.f, 50.f},
                    },
            .source =
                    PixelSource{
                            .solidColor = half3(0.f, 0.f, 0.f),
                    },
            .alpha = 1,
    };

    // Four combinations of settings are used (two transforms here, and drawShadowLayers is
    // called with two different destination data spaces) They're all rounded rect.
    // Three of these are cache misses that generate new shaders.
    // The first combination generates a short and simple shadow shader.
    // The second combination, flip transform, generates two shaders. The first appears to involve
    //   gaussian_fp. The second is a long and general purpose shadow shader with a device space
    //   transformation stage.
    // The third combination is a cache hit, nothing new.
    // The fourth combination, flip transform with a non-SRGB destination dataspace, is new.
    //   It is unique in that nearly everything is done in the vertex shader, and that vertex shader
    //   requires color correction. This is triggered differently from every other instance of color
    //   correction. All other instances are triggered when src and dst dataspaces differ, while
    //   this one is triggered by the destination being non-srgb. Apparently since the third
    //   combination is a cache hit, this color correction is only added when the vertex shader is
    //   doing something non-trivial.
    for (auto transform : {mat4(), kFlip}) {
        layer.geometry.positionTransform = transform;
        caster.geometry.positionTransform = transform;

        auto layers = std::vector<LayerSettings>{layer, caster};
        renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache,
                                 base::unique_fd());
    }
}

static void drawImageLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                            const std::shared_ptr<ExternalTexture>& dstTexture,
                            const std::shared_ptr<ExternalTexture>& srcTexture) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    LayerSettings layer{
            .geometry =
                    Geometry{
                            // The position transform doesn't matter when the reduced shader mode
                            // in in effect. A matrix transform stage is always included.
                            .positionTransform = mat4(),
                            .boundaries = rect,
                            .roundedCornersCrop = rect,
                    },
            .source = PixelSource{.buffer =
                                          Buffer{
                                                  .buffer = srcTexture,
                                                  .maxLuminanceNits = 1000.f,
                                          }},
    };

    for (auto dataspace : {kDestDataSpace, kOtherDataSpace}) {
        layer.sourceDataspace = dataspace;
        // Cache shaders for both rects and round rects.
        // In reduced shader mode, all non-zero round rect radii get the same code path.
        for (float roundedCornersRadius : {0.0f, 50.0f}) {
            // roundedCornersCrop is always set, but the radius triggers the behavior
            layer.geometry.roundedCornersRadius = {roundedCornersRadius, roundedCornersRadius};
            for (bool isOpaque : {true, false}) {
                layer.source.buffer.isOpaque = isOpaque;
                for (auto alpha : {half(.2f), half(1.0f)}) {
                    layer.alpha = alpha;
                    auto layers = std::vector<LayerSettings>{layer};
                    renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache,
                                             base::unique_fd());
                }
            }
        }
    }
}

static void drawSolidLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                            const std::shared_ptr<ExternalTexture>& dstTexture) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                    },
            .source =
                    PixelSource{
                            .solidColor = half3(0.1f, 0.2f, 0.3f),
                    },
            .alpha = 0.5,
    };

    for (auto transform : {mat4(), kScaleAndTranslate}) {
        layer.geometry.positionTransform = transform;
        for (float roundedCornersRadius : {0.0f, 50.f}) {
            layer.geometry.roundedCornersRadius = {roundedCornersRadius, roundedCornersRadius};
            auto layers = std::vector<LayerSettings>{layer};
            renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache,
                                     base::unique_fd());
        }
    }
}

static void drawBlurLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                           const std::shared_ptr<ExternalTexture>& dstTexture) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                    },
            .alpha = 1,
            // setting this is mandatory for shadows and blurs
            .skipContentDraw = true,
    };

    // Different blur code is invoked for radii less and greater than 30 pixels
    for (int radius : {9, 60}) {
        layer.backgroundBlurRadius = radius;
        auto layers = std::vector<LayerSettings>{layer};
        renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache,
                                 base::unique_fd());
    }
}

// The unique feature of these layers is that the boundary is slightly smaller than the rounded
// rect crop, so the rounded edges intersect that boundary and require a different clipping method.
// For buffers, this is done with a stage that computes coverage and it will differ for round and
// elliptical corners.
static void drawClippedLayers(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                              const std::shared_ptr<ExternalTexture>& dstTexture,
                              const std::shared_ptr<ExternalTexture>& srcTexture) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height() - 20); // boundary is smaller

    PixelSource bufferSource{.buffer = Buffer{
                                     .buffer = srcTexture,
                                     .isOpaque = 0,
                                     .maxLuminanceNits = 1000.f,
                             }};
    PixelSource bufferOpaque{.buffer = Buffer{
                                     .buffer = srcTexture,
                                     .isOpaque = 1,
                                     .maxLuminanceNits = 1000.f,
                             }};
    PixelSource colorSource{.solidColor = half3(0.1f, 0.2f, 0.3f)};

    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = rect,
                            .roundedCornersRadius = {27.f, 27.f},
                            .roundedCornersCrop =
                                    FloatRect(0, 0, displayRect.width(), displayRect.height()),
                    },
    };

    for (auto pixelSource : {bufferSource, bufferOpaque, colorSource}) {
        layer.source = pixelSource;
        for (auto dataspace : {kDestDataSpace, kOtherDataSpace}) {
            layer.sourceDataspace = dataspace;
            // Produce a CircularRRect clip and an EllipticalRRect clip.
            for (auto transform : {kScaleAndTranslate, kScaleAsymmetric}) {
                layer.geometry.positionTransform = transform;
                for (float alpha : {0.5f, 1.f}) {
                    layer.alpha = alpha;
                    auto layers = std::vector<LayerSettings>{layer};
                    renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache,
                                             base::unique_fd());
                }
            }
        }
    }
}

static void drawPIPImageLayer(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                            const std::shared_ptr<ExternalTexture>& dstTexture,
                            const std::shared_ptr<ExternalTexture>& srcTexture) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    LayerSettings layer{
            .geometry =
                    Geometry{
                            // Note that this flip matrix only makes a difference when clipping,
                            // which happens in this layer because the roundrect crop is just a bit
                            // larger than the layer bounds.
                            .positionTransform = kFlip,
                            .boundaries = rect,
                            .roundedCornersRadius = {94.2551f, 94.2551f},
                            .roundedCornersCrop = FloatRect(-93.75, 0, displayRect.width() + 93.75,
                                                            displayRect.height()),
                    },
            .source = PixelSource{.buffer =
                                          Buffer{
                                                  .buffer = srcTexture,
                                                  .maxLuminanceNits = 1000.f,
                                                  .isOpaque = 0,
                                                  .usePremultipliedAlpha = 1,
                                          }},
            .sourceDataspace = kOtherDataSpace,
            .alpha = 1,

    };

    auto layers = std::vector<LayerSettings>{layer};
    renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache, base::unique_fd());
}

static void drawHolePunchLayer(SkiaRenderEngine* renderengine, const DisplaySettings& display,
                            const std::shared_ptr<ExternalTexture>& dstTexture) {
    const Rect& displayRect = display.physicalDisplay;
    FloatRect rect(0, 0, displayRect.width(), displayRect.height());
    FloatRect small(0, 0, displayRect.width()-20, displayRect.height()+20);
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .positionTransform = kScaleAndTranslate,
                            // the boundaries have to be smaller than the rounded crop so that
                            // clipRRect is used instead of drawRRect
                            .boundaries = small,
                            .roundedCornersRadius = {50.f, 50.f},
                            .roundedCornersCrop = rect,
                    },
            .source =
                    PixelSource{
                            .solidColor = half3(0.f, 0.f, 0.f),
                    },
            .sourceDataspace = kDestDataSpace,
            .alpha = 0,
            .disableBlending = true,

    };

    auto layers = std::vector<LayerSettings>{layer};
    renderengine->drawLayers(display, layers, dstTexture, kUseFrameBufferCache, base::unique_fd());
}

//
// The collection of shaders cached here were found by using perfetto to record shader compiles
// during actions that involve RenderEngine, logging the layer settings, and the shader code
// and reproducing those settings here.
//
// It is helpful when debugging this to turn on
// in SkGLRenderEngine.cpp:
//    kPrintLayerSettings = true
//    kFlushAfterEveryLayer = true
// in external/skia/src/gpu/gl/builders/GrGLShaderStringBuilder.cpp
//    gPrintSKSL = true
void Cache::primeShaderCache(SkiaRenderEngine* renderengine) {
    const int previousCount = renderengine->reportShadersCompiled();
    if (previousCount) {
        ALOGD("%d Shaders already compiled before Cache::primeShaderCache ran\n", previousCount);
    }

    // The loop is beneficial for debugging and should otherwise be optimized out by the compiler.
    // Adding additional bounds to the loop is useful for verifying that the size of the dst buffer
    // does not impact the shader compilation counts by triggering different behaviors in RE/Skia.
    for (SkSize bounds : {SkSize::Make(128, 128), /*SkSize::Make(1080, 2340)*/}) {
        const nsecs_t timeBefore = systemTime();
        // The dimensions should not matter, so long as we draw inside them.
        const Rect displayRect(0, 0, bounds.fWidth, bounds.fHeight);
        DisplaySettings display{
                .physicalDisplay = displayRect,
                .clip = displayRect,
                .maxLuminance = 500,
                .outputDataspace = kDestDataSpace,
        };
        DisplaySettings p3Display{
                .physicalDisplay = displayRect,
                .clip = displayRect,
                .maxLuminance = 500,
                .outputDataspace = kOtherDataSpace,
        };

        const int64_t usage = GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE;

        sp<GraphicBuffer> dstBuffer =
                new GraphicBuffer(displayRect.width(), displayRect.height(), PIXEL_FORMAT_RGBA_8888,
                                  1, usage, "primeShaderCache_dst");

        const auto dstTexture =
                std::make_shared<impl::ExternalTexture>(dstBuffer, *renderengine,
                                                        impl::ExternalTexture::Usage::WRITEABLE);
        // This buffer will be the source for the call to drawImageLayers. Draw
        // something to it as a placeholder for what an app draws. We should draw
        // something, but the details are not important. Make use of the shadow layer drawing step
        // to populate it.
        sp<GraphicBuffer> srcBuffer =
                new GraphicBuffer(displayRect.width(), displayRect.height(), PIXEL_FORMAT_RGBA_8888,
                                  1, usage, "drawImageLayer_src");

        const auto srcTexture = std::make_shared<
                impl::ExternalTexture>(srcBuffer, *renderengine,
                                       impl::ExternalTexture::Usage::READABLE |
                                               impl::ExternalTexture::Usage::WRITEABLE);
        drawHolePunchLayer(renderengine, display, dstTexture);
        drawSolidLayers(renderengine, display, dstTexture);

        drawShadowLayers(renderengine, display, srcTexture);
        drawShadowLayers(renderengine, p3Display, srcTexture);

        if (renderengine->supportsBackgroundBlur()) {
            drawBlurLayers(renderengine, display, dstTexture);
        }

        // The majority of skia shaders needed by RenderEngine are related to sampling images.
        // These need to be generated with various source textures.
        // Make a list of applicable sources.
        // GRALLOC_USAGE_HW_TEXTURE should be the same as AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE.
        const int64_t usageExternal = GRALLOC_USAGE_HW_TEXTURE;
        sp<GraphicBuffer> externalBuffer =
                new GraphicBuffer(displayRect.width(), displayRect.height(), PIXEL_FORMAT_RGBA_8888,
                                  1, usageExternal, "primeShaderCache_external");
        const auto externalTexture =
                std::make_shared<impl::ExternalTexture>(externalBuffer, *renderengine,
                                                        impl::ExternalTexture::Usage::READABLE);
        std::vector<const std::shared_ptr<ExternalTexture>> textures =
            {srcTexture, externalTexture};

        // Another external texture with a different pixel format triggers useIsOpaqueWorkaround.
        // It doesn't have to be f16, but it can't be the usual 8888.
        sp<GraphicBuffer> f16ExternalBuffer =
                new GraphicBuffer(displayRect.width(), displayRect.height(), PIXEL_FORMAT_RGBA_FP16,
                                  1, usageExternal, "primeShaderCache_external_f16");
        // The F16 texture may not be usable on all devices, so check first that it was created.
        status_t error = f16ExternalBuffer->initCheck();
        if (!error) {
            const auto f16ExternalTexture =
                    std::make_shared<impl::ExternalTexture>(f16ExternalBuffer, *renderengine,
                                                            impl::ExternalTexture::Usage::READABLE);
            textures.push_back(f16ExternalTexture);
        }

        for (auto texture : textures) {
            drawImageLayers(renderengine, display, dstTexture, texture);
            // Draw layers for b/185569240.
            drawClippedLayers(renderengine, display, dstTexture, texture);
        }

        drawPIPImageLayer(renderengine, display, dstTexture, externalTexture);

        // draw one final layer synchronously to force GL submit
        LayerSettings layer{
                .source = PixelSource{.solidColor = half3(0.f, 0.f, 0.f)},
        };
        auto layers = std::vector<LayerSettings>{layer};
        // call get() to make it synchronous
        renderengine
                ->drawLayers(display, layers, dstTexture, kUseFrameBufferCache, base::unique_fd())
                .get();

        const nsecs_t timeAfter = systemTime();
        const float compileTimeMs = static_cast<float>(timeAfter - timeBefore) / 1.0E6;
        const int shadersCompiled = renderengine->reportShadersCompiled() - previousCount;
        ALOGD("Shader cache generated %d shaders in %f ms\n", shadersCompiled, compileTimeMs);
    }
}

} // namespace android::renderengine::skia
