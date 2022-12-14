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

#include <RenderEngineBench.h>
#include <android-base/file.h>
#include <benchmark/benchmark.h>
#include <gui/SurfaceComposerClient.h>
#include <log/log.h>
#include <renderengine/ExternalTexture.h>
#include <renderengine/LayerSettings.h>
#include <renderengine/RenderEngine.h>
#include <renderengine/impl/ExternalTexture.h>

#include <mutex>

using namespace android;
using namespace android::renderengine;

///////////////////////////////////////////////////////////////////////////////
//  Helpers for Benchmark::Apply
///////////////////////////////////////////////////////////////////////////////

std::string RenderEngineTypeName(RenderEngine::RenderEngineType type) {
    switch (type) {
        case RenderEngine::RenderEngineType::SKIA_GL_THREADED:
            return "skiaglthreaded";
        case RenderEngine::RenderEngineType::SKIA_GL:
            return "skiagl";
        case RenderEngine::RenderEngineType::GLES:
        case RenderEngine::RenderEngineType::THREADED:
            LOG_ALWAYS_FATAL("GLESRenderEngine is deprecated - why time it?");
            return "unused";
    }
}

/**
 * Passed (indirectly - see RunSkiaGLThreaded) to Benchmark::Apply to create a
 * Benchmark which specifies which RenderEngineType it uses.
 *
 * This simplifies calling ->Arg(type)->Arg(type) and provides strings to make
 * it obvious which version is being run.
 *
 * @param b The benchmark family
 * @param type The type of RenderEngine to use.
 */
static void AddRenderEngineType(benchmark::internal::Benchmark* b,
                                RenderEngine::RenderEngineType type) {
    b->Arg(static_cast<int64_t>(type));
    b->ArgName(RenderEngineTypeName(type));
}

/**
 * Run a benchmark once using SKIA_GL_THREADED.
 */
static void RunSkiaGLThreaded(benchmark::internal::Benchmark* b) {
    AddRenderEngineType(b, RenderEngine::RenderEngineType::SKIA_GL_THREADED);
}

///////////////////////////////////////////////////////////////////////////////
//  Helpers for calling drawLayers
///////////////////////////////////////////////////////////////////////////////

std::pair<uint32_t, uint32_t> getDisplaySize() {
    // These will be retrieved from a ui::Size, which stores int32_t, but they will be passed
    // to GraphicBuffer, which wants uint32_t.
    static uint32_t width, height;
    std::once_flag once;
    std::call_once(once, []() {
        auto surfaceComposerClient = SurfaceComposerClient::getDefault();
        auto displayToken = surfaceComposerClient->getInternalDisplayToken();
        ui::DisplayMode displayMode;
        if (surfaceComposerClient->getActiveDisplayMode(displayToken, &displayMode) < 0) {
            LOG_ALWAYS_FATAL("Failed to get active display mode!");
        }
        auto w = displayMode.resolution.width;
        auto h = displayMode.resolution.height;
        LOG_ALWAYS_FATAL_IF(w <= 0 || h <= 0, "Invalid display size!");
        width = static_cast<uint32_t>(w);
        height = static_cast<uint32_t>(h);
    });
    return std::pair<uint32_t, uint32_t>(width, height);
}

// This value doesn't matter, as it's not read. TODO(b/199918329): Once we remove
// GLESRenderEngine we can remove this, too.
static constexpr const bool kUseFrameBufferCache = false;

static std::unique_ptr<RenderEngine> createRenderEngine(RenderEngine::RenderEngineType type) {
    auto args = RenderEngineCreationArgs::Builder()
                        .setPixelFormat(static_cast<int>(ui::PixelFormat::RGBA_8888))
                        .setImageCacheSize(1)
                        .setEnableProtectedContext(true)
                        .setPrecacheToneMapperShaderOnly(false)
                        .setSupportsBackgroundBlur(true)
                        .setContextPriority(RenderEngine::ContextPriority::REALTIME)
                        .setRenderEngineType(type)
                        .setUseColorManagerment(true)
                        .build();
    return RenderEngine::create(args);
}

static std::shared_ptr<ExternalTexture> allocateBuffer(RenderEngine& re, uint32_t width,
                                                       uint32_t height,
                                                       uint64_t extraUsageFlags = 0,
                                                       std::string name = "output") {
    return std::make_shared<
            impl::ExternalTexture>(new GraphicBuffer(width, height, HAL_PIXEL_FORMAT_RGBA_8888, 1,
                                                     GRALLOC_USAGE_HW_RENDER |
                                                             GRALLOC_USAGE_HW_TEXTURE |
                                                             extraUsageFlags,
                                                     std::move(name)),
                                   re,
                                   impl::ExternalTexture::Usage::READABLE |
                                           impl::ExternalTexture::Usage::WRITEABLE);
}

static std::shared_ptr<ExternalTexture> copyBuffer(RenderEngine& re,
                                                   std::shared_ptr<ExternalTexture> original,
                                                   uint64_t extraUsageFlags, std::string name) {
    const uint32_t width = original->getBuffer()->getWidth();
    const uint32_t height = original->getBuffer()->getHeight();
    auto texture = allocateBuffer(re, width, height, extraUsageFlags, name);

    const Rect displayRect(0, 0, static_cast<int32_t>(width), static_cast<int32_t>(height));
    DisplaySettings display{
            .physicalDisplay = displayRect,
            .clip = displayRect,
            .maxLuminance = 500,
    };

    const FloatRect layerRect(0, 0, width, height);
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = layerRect,
                    },
            .source =
                    PixelSource{
                            .buffer =
                                    Buffer{
                                            .buffer = original,
                                    },
                    },
            .alpha = half(1.0f),
    };
    auto layers = std::vector<LayerSettings>{layer};

    auto [status, drawFence] =
            re.drawLayers(display, layers, texture, kUseFrameBufferCache, base::unique_fd()).get();
    sp<Fence> waitFence = sp<Fence>::make(std::move(drawFence));
    waitFence->waitForever(LOG_TAG);
    return texture;
}

/**
 * Helper for timing calls to drawLayers.
 *
 * Caller needs to create RenderEngine and the LayerSettings, and this takes
 * care of setting up the display, starting and stopping the timer, calling
 * drawLayers, and saving (if --save is used).
 *
 * This times both the CPU and GPU work initiated by drawLayers. All work done
 * outside of the for loop is excluded from the timing measurements.
 */
static void benchDrawLayers(RenderEngine& re, const std::vector<LayerSettings>& layers,
                            benchmark::State& benchState, const char* saveFileName) {
    auto [width, height] = getDisplaySize();
    auto outputBuffer = allocateBuffer(re, width, height);

    const Rect displayRect(0, 0, static_cast<int32_t>(width), static_cast<int32_t>(height));
    DisplaySettings display{
            .physicalDisplay = displayRect,
            .clip = displayRect,
            .maxLuminance = 500,
    };

    // This loop starts and stops the timer.
    for (auto _ : benchState) {
        auto [status, drawFence] = re.drawLayers(display, layers, outputBuffer,
                                                 kUseFrameBufferCache, base::unique_fd())
                                           .get();
        sp<Fence> waitFence = sp<Fence>::make(std::move(drawFence));
        waitFence->waitForever(LOG_TAG);
    }

    if (renderenginebench::save() && saveFileName) {
        // Copy to a CPU-accessible buffer so we can encode it.
        outputBuffer = copyBuffer(re, outputBuffer, GRALLOC_USAGE_SW_READ_OFTEN, "to_encode");

        std::string outFile = base::GetExecutableDirectory();
        outFile.append("/");
        outFile.append(saveFileName);
        outFile.append(".jpg");
        renderenginebench::encodeToJpeg(outFile.c_str(), outputBuffer->getBuffer());
    }
}

///////////////////////////////////////////////////////////////////////////////
//  Benchmarks
///////////////////////////////////////////////////////////////////////////////

void BM_blur(benchmark::State& benchState) {
    auto re = createRenderEngine(static_cast<RenderEngine::RenderEngineType>(benchState.range()));

    // Initially use cpu access so we can decode into it with AImageDecoder.
    auto [width, height] = getDisplaySize();
    auto srcBuffer =
            allocateBuffer(*re, width, height, GRALLOC_USAGE_SW_WRITE_OFTEN, "decoded_source");
    {
        std::string srcImage = base::GetExecutableDirectory();
        srcImage.append("/resources/homescreen.png");
        renderenginebench::decode(srcImage.c_str(), srcBuffer->getBuffer());

        // Now copy into GPU-only buffer for more realistic timing.
        srcBuffer = copyBuffer(*re, srcBuffer, 0, "source");
    }

    const FloatRect layerRect(0, 0, width, height);
    LayerSettings layer{
            .geometry =
                    Geometry{
                            .boundaries = layerRect,
                    },
            .source =
                    PixelSource{
                            .buffer =
                                    Buffer{
                                            .buffer = srcBuffer,
                                    },
                    },
            .alpha = half(1.0f),
    };
    LayerSettings blurLayer{
            .geometry =
                    Geometry{
                            .boundaries = layerRect,
                    },
            .alpha = half(1.0f),
            .skipContentDraw = true,
            .backgroundBlurRadius = 60,
    };

    auto layers = std::vector<LayerSettings>{layer, blurLayer};
    benchDrawLayers(*re, layers, benchState, "blurred");
}

BENCHMARK(BM_blur)->Apply(RunSkiaGLThreaded);
