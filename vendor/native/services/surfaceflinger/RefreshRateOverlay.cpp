/*
 * Copyright 2019 The Android Open Source Project
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

#include <algorithm>

#include "BackgroundExecutor.h"
#include "Client.h"
#include "Layer.h"
#include "RefreshRateOverlay.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include <SkCanvas.h>
#include <SkPaint.h>
#pragma clang diagnostic pop
#include <SkBlendMode.h>
#include <SkRect.h>
#include <SkSurface.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/SurfaceControl.h>

#undef LOG_TAG
#define LOG_TAG "RefreshRateOverlay"

namespace android {
namespace {

constexpr int kDigitWidth = 64;
constexpr int kDigitHeight = 100;
constexpr int kDigitSpace = 16;

// Layout is digit, space, digit, space, digit, space, spinner.
constexpr int kBufferWidth = 4 * kDigitWidth + 3 * kDigitSpace;
constexpr int kBufferHeight = kDigitHeight;

SurfaceComposerClient::Transaction createTransaction(const sp<SurfaceControl>& surface) {
    constexpr float kFrameRate = 0.f;
    constexpr int8_t kCompatibility = ANATIVEWINDOW_FRAME_RATE_NO_VOTE;
    constexpr int8_t kSeamlessness = ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS;

    return SurfaceComposerClient::Transaction().setFrameRate(surface, kFrameRate, kCompatibility,
                                                             kSeamlessness);
}

} // namespace

SurfaceControlHolder::~SurfaceControlHolder() {
    // Hand the sp<SurfaceControl> to the helper thread to release the last
    // reference. This makes sure that the SurfaceControl is destructed without
    // SurfaceFlinger::mStateLock held.
    BackgroundExecutor::getInstance().sendCallbacks(
            {[sc = std::move(mSurfaceControl)]() mutable { sc.clear(); }});
}

void RefreshRateOverlay::SevenSegmentDrawer::drawSegment(Segment segment, int left, SkColor color,
                                                         SkCanvas& canvas) {
    const SkRect rect = [&]() {
        switch (segment) {
            case Segment::Upper:
                return SkRect::MakeLTRB(left, 0, left + kDigitWidth, kDigitSpace);
            case Segment::UpperLeft:
                return SkRect::MakeLTRB(left, 0, left + kDigitSpace, kDigitHeight / 2);
            case Segment::UpperRight:
                return SkRect::MakeLTRB(left + kDigitWidth - kDigitSpace, 0, left + kDigitWidth,
                                        kDigitHeight / 2);
            case Segment::Middle:
                return SkRect::MakeLTRB(left, kDigitHeight / 2 - kDigitSpace / 2,
                                        left + kDigitWidth, kDigitHeight / 2 + kDigitSpace / 2);
            case Segment::LowerLeft:
                return SkRect::MakeLTRB(left, kDigitHeight / 2, left + kDigitSpace, kDigitHeight);
            case Segment::LowerRight:
                return SkRect::MakeLTRB(left + kDigitWidth - kDigitSpace, kDigitHeight / 2,
                                        left + kDigitWidth, kDigitHeight);
            case Segment::Bottom:
                return SkRect::MakeLTRB(left, kDigitHeight - kDigitSpace, left + kDigitWidth,
                                        kDigitHeight);
        }
    }();

    SkPaint paint;
    paint.setColor(color);
    paint.setBlendMode(SkBlendMode::kSrc);
    canvas.drawRect(rect, paint);
}

void RefreshRateOverlay::SevenSegmentDrawer::drawDigit(int digit, int left, SkColor color,
                                                       SkCanvas& canvas) {
    if (digit < 0 || digit > 9) return;

    if (digit == 0 || digit == 2 || digit == 3 || digit == 5 || digit == 6 || digit == 7 ||
        digit == 8 || digit == 9)
        drawSegment(Segment::Upper, left, color, canvas);
    if (digit == 0 || digit == 4 || digit == 5 || digit == 6 || digit == 8 || digit == 9)
        drawSegment(Segment::UpperLeft, left, color, canvas);
    if (digit == 0 || digit == 1 || digit == 2 || digit == 3 || digit == 4 || digit == 7 ||
        digit == 8 || digit == 9)
        drawSegment(Segment::UpperRight, left, color, canvas);
    if (digit == 2 || digit == 3 || digit == 4 || digit == 5 || digit == 6 || digit == 8 ||
        digit == 9)
        drawSegment(Segment::Middle, left, color, canvas);
    if (digit == 0 || digit == 2 || digit == 6 || digit == 8)
        drawSegment(Segment::LowerLeft, left, color, canvas);
    if (digit == 0 || digit == 1 || digit == 3 || digit == 4 || digit == 5 || digit == 6 ||
        digit == 7 || digit == 8 || digit == 9)
        drawSegment(Segment::LowerRight, left, color, canvas);
    if (digit == 0 || digit == 2 || digit == 3 || digit == 5 || digit == 6 || digit == 8 ||
        digit == 9)
        drawSegment(Segment::Bottom, left, color, canvas);
}

auto RefreshRateOverlay::SevenSegmentDrawer::draw(int number, SkColor color,
                                                  ui::Transform::RotationFlags rotation,
                                                  bool showSpinner) -> Buffers {
    if (number < 0 || number > 1000) return {};

    const auto hundreds = number / 100;
    const auto tens = (number / 10) % 10;
    const auto ones = number % 10;

    const size_t loopCount = showSpinner ? 6 : 1;

    Buffers buffers;
    buffers.reserve(loopCount);

    for (size_t i = 0; i < loopCount; i++) {
        // Pre-rotate the buffer before it reaches SurfaceFlinger.
        SkMatrix canvasTransform = SkMatrix();
        const auto [bufferWidth, bufferHeight] = [&]() -> std::pair<int, int> {
            switch (rotation) {
                case ui::Transform::ROT_90:
                    canvasTransform.setTranslate(kBufferHeight, 0);
                    canvasTransform.preRotate(90.f);
                    return {kBufferHeight, kBufferWidth};
                case ui::Transform::ROT_270:
                    canvasTransform.setRotate(270.f, kBufferWidth / 2.f, kBufferWidth / 2.f);
                    return {kBufferHeight, kBufferWidth};
                default:
                    return {kBufferWidth, kBufferHeight};
            }
        }();

        sp<GraphicBuffer> buffer =
                new GraphicBuffer(static_cast<uint32_t>(bufferWidth),
                                  static_cast<uint32_t>(bufferHeight), HAL_PIXEL_FORMAT_RGBA_8888,
                                  1,
                                  GRALLOC_USAGE_SW_WRITE_RARELY | GRALLOC_USAGE_HW_COMPOSER |
                                          GRALLOC_USAGE_HW_TEXTURE,
                                  "RefreshRateOverlayBuffer");

        const status_t bufferStatus = buffer->initCheck();
        LOG_ALWAYS_FATAL_IF(bufferStatus != OK, "RefreshRateOverlay: Buffer failed to allocate: %d",
                            bufferStatus);

        sk_sp<SkSurface> surface = SkSurface::MakeRasterN32Premul(bufferWidth, bufferHeight);
        SkCanvas* canvas = surface->getCanvas();
        canvas->setMatrix(canvasTransform);

        int left = 0;
        if (hundreds != 0) {
            drawDigit(hundreds, left, color, *canvas);
        }
        left += kDigitWidth + kDigitSpace;

        if (tens != 0) {
            drawDigit(tens, left, color, *canvas);
        }
        left += kDigitWidth + kDigitSpace;

        drawDigit(ones, left, color, *canvas);
        left += kDigitWidth + kDigitSpace;

        if (showSpinner) {
            switch (i) {
                case 0:
                    drawSegment(Segment::Upper, left, color, *canvas);
                    break;
                case 1:
                    drawSegment(Segment::UpperRight, left, color, *canvas);
                    break;
                case 2:
                    drawSegment(Segment::LowerRight, left, color, *canvas);
                    break;
                case 3:
                    drawSegment(Segment::Bottom, left, color, *canvas);
                    break;
                case 4:
                    drawSegment(Segment::LowerLeft, left, color, *canvas);
                    break;
                case 5:
                    drawSegment(Segment::UpperLeft, left, color, *canvas);
                    break;
            }
        }

        void* pixels = nullptr;
        buffer->lock(GRALLOC_USAGE_SW_WRITE_RARELY, reinterpret_cast<void**>(&pixels));

        const SkImageInfo& imageInfo = surface->imageInfo();
        const size_t dstRowBytes =
                buffer->getStride() * static_cast<size_t>(imageInfo.bytesPerPixel());

        canvas->readPixels(imageInfo, pixels, dstRowBytes, 0, 0);
        buffer->unlock();
        buffers.push_back(std::move(buffer));
    }
    return buffers;
}

std::unique_ptr<SurfaceControlHolder> createSurfaceControlHolder() {
    sp<SurfaceControl> surfaceControl =
            SurfaceComposerClient::getDefault()
                    ->createSurface(String8("RefreshRateOverlay"), kBufferWidth, kBufferHeight,
                                    PIXEL_FORMAT_RGBA_8888,
                                    ISurfaceComposerClient::eFXSurfaceBufferState);
    return std::make_unique<SurfaceControlHolder>(std::move(surfaceControl));
}

RefreshRateOverlay::RefreshRateOverlay(FpsRange fpsRange, bool showSpinner)
      : mFpsRange(fpsRange),
        mShowSpinner(showSpinner),
        mSurfaceControl(createSurfaceControlHolder()) {
    if (!mSurfaceControl) {
        ALOGE("%s: Failed to create buffer state layer", __func__);
        return;
    }

    createTransaction(mSurfaceControl->get())
            .setLayer(mSurfaceControl->get(), INT32_MAX - 2)
            .setTrustedOverlay(mSurfaceControl->get(), true)
            .apply();
}

auto RefreshRateOverlay::getOrCreateBuffers(Fps fps) -> const Buffers& {
    static const Buffers kNoBuffers;
    if (!mSurfaceControl) return kNoBuffers;

    const auto transformHint =
            static_cast<ui::Transform::RotationFlags>(mSurfaceControl->get()->getTransformHint());

    // Tell SurfaceFlinger about the pre-rotation on the buffer.
    const auto transform = [&] {
        switch (transformHint) {
            case ui::Transform::ROT_90:
                return ui::Transform::ROT_270;
            case ui::Transform::ROT_270:
                return ui::Transform::ROT_90;
            default:
                return ui::Transform::ROT_0;
        }
    }();

    createTransaction(mSurfaceControl->get())
            .setTransform(mSurfaceControl->get(), transform)
            .apply();

    BufferCache::const_iterator it = mBufferCache.find({fps.getIntValue(), transformHint});
    if (it == mBufferCache.end()) {
        const int minFps = mFpsRange.min.getIntValue();
        const int maxFps = mFpsRange.max.getIntValue();

        // Clamp to the range. The current fps may be outside of this range if the display has
        // changed its set of supported refresh rates.
        const int intFps = std::clamp(fps.getIntValue(), minFps, maxFps);

        // Ensure non-zero range to avoid division by zero.
        const float fpsScale = static_cast<float>(intFps - minFps) / std::max(1, maxFps - minFps);

        constexpr SkColor kMinFpsColor = SK_ColorRED;
        constexpr SkColor kMaxFpsColor = SK_ColorGREEN;
        constexpr float kAlpha = 0.8f;

        SkColor4f colorBase = SkColor4f::FromColor(kMaxFpsColor) * fpsScale;
        const SkColor4f minFpsColor = SkColor4f::FromColor(kMinFpsColor) * (1 - fpsScale);

        colorBase.fR = colorBase.fR + minFpsColor.fR;
        colorBase.fG = colorBase.fG + minFpsColor.fG;
        colorBase.fB = colorBase.fB + minFpsColor.fB;
        colorBase.fA = kAlpha;

        const SkColor color = colorBase.toSkColor();

        auto buffers = SevenSegmentDrawer::draw(intFps, color, transformHint, mShowSpinner);
        it = mBufferCache.try_emplace({intFps, transformHint}, std::move(buffers)).first;
    }

    return it->second;
}

void RefreshRateOverlay::setViewport(ui::Size viewport) {
    constexpr int32_t kMaxWidth = 1000;
    const auto width = std::min({kMaxWidth, viewport.width, viewport.height});
    const auto height = 2 * width;
    Rect frame((3 * width) >> 4, height >> 5);
    frame.offsetBy(width >> 5, height >> 4);

    createTransaction(mSurfaceControl->get())
            .setMatrix(mSurfaceControl->get(), frame.getWidth() / static_cast<float>(kBufferWidth),
                       0, 0, frame.getHeight() / static_cast<float>(kBufferHeight))
            .setPosition(mSurfaceControl->get(), frame.left, frame.top)
            .apply();
}

void RefreshRateOverlay::setLayerStack(ui::LayerStack stack) {
    createTransaction(mSurfaceControl->get()).setLayerStack(mSurfaceControl->get(), stack).apply();
}

void RefreshRateOverlay::changeRefreshRate(Fps fps) {
    mCurrentFps = fps;
    const auto buffer = getOrCreateBuffers(fps)[mFrame];
    createTransaction(mSurfaceControl->get()).setBuffer(mSurfaceControl->get(), buffer).apply();
}

void RefreshRateOverlay::animate() {
    if (!mShowSpinner || !mCurrentFps) return;

    const auto& buffers = getOrCreateBuffers(*mCurrentFps);
    mFrame = (mFrame + 1) % buffers.size();
    const auto buffer = buffers[mFrame];
    createTransaction(mSurfaceControl->get()).setBuffer(mSurfaceControl->get(), buffer).apply();
}

} // namespace android
