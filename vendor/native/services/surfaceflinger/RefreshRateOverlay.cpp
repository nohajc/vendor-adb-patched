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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include "RefreshRateOverlay.h"
#include "Client.h"
#include "Layer.h"

#include <gui/IProducerListener.h>

#undef LOG_TAG
#define LOG_TAG "RefreshRateOverlay"

namespace android {

void RefreshRateOverlay::SevenSegmentDrawer::drawRect(const Rect& r, const half4& color,
                                                      const sp<GraphicBuffer>& buffer,
                                                      uint8_t* pixels) {
    for (int32_t j = r.top; j < r.bottom; j++) {
        if (j >= buffer->getHeight()) {
            break;
        }

        for (int32_t i = r.left; i < r.right; i++) {
            if (i >= buffer->getWidth()) {
                break;
            }

            uint8_t* iter = pixels + 4 * (i + (buffer->getStride() * j));
            iter[0] = uint8_t(color.r * 255);
            iter[1] = uint8_t(color.g * 255);
            iter[2] = uint8_t(color.b * 255);
            iter[3] = uint8_t(color.a * 255);
        }
    }
}

void RefreshRateOverlay::SevenSegmentDrawer::drawSegment(Segment segment, int left,
                                                         const half4& color,
                                                         const sp<GraphicBuffer>& buffer,
                                                         uint8_t* pixels) {
    const Rect rect = [&]() {
        switch (segment) {
            case Segment::Upper:
                return Rect(left, 0, left + DIGIT_WIDTH, DIGIT_SPACE);
            case Segment::UpperLeft:
                return Rect(left, 0, left + DIGIT_SPACE, DIGIT_HEIGHT / 2);
            case Segment::UpperRight:
                return Rect(left + DIGIT_WIDTH - DIGIT_SPACE, 0, left + DIGIT_WIDTH,
                            DIGIT_HEIGHT / 2);
            case Segment::Middle:
                return Rect(left, DIGIT_HEIGHT / 2 - DIGIT_SPACE / 2, left + DIGIT_WIDTH,
                            DIGIT_HEIGHT / 2 + DIGIT_SPACE / 2);
            case Segment::LowerLeft:
                return Rect(left, DIGIT_HEIGHT / 2, left + DIGIT_SPACE, DIGIT_HEIGHT);
            case Segment::LowerRight:
                return Rect(left + DIGIT_WIDTH - DIGIT_SPACE, DIGIT_HEIGHT / 2, left + DIGIT_WIDTH,
                            DIGIT_HEIGHT);
            case Segment::Buttom:
                return Rect(left, DIGIT_HEIGHT - DIGIT_SPACE, left + DIGIT_WIDTH, DIGIT_HEIGHT);
        }
    }();

    drawRect(rect, color, buffer, pixels);
}

void RefreshRateOverlay::SevenSegmentDrawer::drawDigit(int digit, int left, const half4& color,
                                                       const sp<GraphicBuffer>& buffer,
                                                       uint8_t* pixels) {
    if (digit < 0 || digit > 9) return;

    if (digit == 0 || digit == 2 || digit == 3 || digit == 5 || digit == 6 || digit == 7 ||
        digit == 8 || digit == 9)
        drawSegment(Segment::Upper, left, color, buffer, pixels);
    if (digit == 0 || digit == 4 || digit == 5 || digit == 6 || digit == 8 || digit == 9)
        drawSegment(Segment::UpperLeft, left, color, buffer, pixels);
    if (digit == 0 || digit == 1 || digit == 2 || digit == 3 || digit == 4 || digit == 7 ||
        digit == 8 || digit == 9)
        drawSegment(Segment::UpperRight, left, color, buffer, pixels);
    if (digit == 2 || digit == 3 || digit == 4 || digit == 5 || digit == 6 || digit == 8 ||
        digit == 9)
        drawSegment(Segment::Middle, left, color, buffer, pixels);
    if (digit == 0 || digit == 2 || digit == 6 || digit == 8)
        drawSegment(Segment::LowerLeft, left, color, buffer, pixels);
    if (digit == 0 || digit == 1 || digit == 3 || digit == 4 || digit == 5 || digit == 6 ||
        digit == 7 || digit == 8 || digit == 9)
        drawSegment(Segment::LowerRight, left, color, buffer, pixels);
    if (digit == 0 || digit == 2 || digit == 3 || digit == 5 || digit == 6 || digit == 8 ||
        digit == 9)
        drawSegment(Segment::Buttom, left, color, buffer, pixels);
}

sp<GraphicBuffer> RefreshRateOverlay::SevenSegmentDrawer::drawNumber(int number,
                                                                     const half4& color) {
    if (number < 0 || number > 1000) return nullptr;

    const auto hundreds = number / 100;
    const auto tens = (number / 10) % 10;
    const auto ones = number % 10;

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(BUFFER_WIDTH, BUFFER_HEIGHT, HAL_PIXEL_FORMAT_RGBA_8888, 1,
                              GRALLOC_USAGE_SW_WRITE_RARELY | GRALLOC_USAGE_HW_COMPOSER |
                                      GRALLOC_USAGE_HW_TEXTURE,
                              "RefreshRateOverlayBuffer");
    uint8_t* pixels;
    buffer->lock(GRALLOC_USAGE_SW_WRITE_RARELY, reinterpret_cast<void**>(&pixels));
    // Clear buffer content
    drawRect(Rect(BUFFER_WIDTH, BUFFER_HEIGHT), half4(0), buffer, pixels);
    int left = 0;
    if (hundreds != 0) {
        drawDigit(hundreds, left, color, buffer, pixels);
        left += DIGIT_WIDTH + DIGIT_SPACE;
    }

    if (tens != 0) {
        drawDigit(tens, left, color, buffer, pixels);
        left += DIGIT_WIDTH + DIGIT_SPACE;
    }

    drawDigit(ones, left, color, buffer, pixels);
    buffer->unlock();
    return buffer;
}

RefreshRateOverlay::RefreshRateOverlay(SurfaceFlinger& flinger)
      : mFlinger(flinger), mClient(new Client(&mFlinger)) {
    createLayer();
    primeCache();
}

bool RefreshRateOverlay::createLayer() {
    const status_t ret =
            mFlinger.createLayer(String8("RefreshRateOverlay"), mClient,
                                 SevenSegmentDrawer::getWidth(), SevenSegmentDrawer::getHeight(),
                                 PIXEL_FORMAT_RGBA_8888,
                                 ISurfaceComposerClient::eFXSurfaceBufferState, LayerMetadata(),
                                 &mIBinder, &mGbp, nullptr);
    if (ret) {
        ALOGE("failed to create buffer state layer");
        return false;
    }

    Mutex::Autolock _l(mFlinger.mStateLock);
    mLayer = mClient->getLayerUser(mIBinder);
    mLayer->setFrameRate(Layer::FrameRate(0, Layer::FrameRateCompatibility::NoVote));

    // setting Layer's Z requires resorting layersSortedByZ
    ssize_t idx = mFlinger.mCurrentState.layersSortedByZ.indexOf(mLayer);
    if (mLayer->setLayer(INT32_MAX - 2) && idx >= 0) {
        mFlinger.mCurrentState.layersSortedByZ.removeAt(idx);
        mFlinger.mCurrentState.layersSortedByZ.add(mLayer);
    }

    return true;
}

void RefreshRateOverlay::primeCache() {
    auto& allRefreshRates = mFlinger.mRefreshRateConfigs->getAllRefreshRates();
    if (allRefreshRates.size() == 1) {
        auto fps = allRefreshRates.begin()->second->getFps();
        half4 color = {LOW_FPS_COLOR, ALPHA};
        mBufferCache.emplace(fps, SevenSegmentDrawer::drawNumber(fps, color));
        return;
    }

    std::vector<uint32_t> supportedFps;
    supportedFps.reserve(allRefreshRates.size());
    for (auto& [ignored, refreshRate] : allRefreshRates) {
        supportedFps.push_back(refreshRate->getFps());
    }

    std::sort(supportedFps.begin(), supportedFps.end());
    const auto mLowFps = supportedFps[0];
    const auto mHighFps = supportedFps[supportedFps.size() - 1];
    for (auto fps : supportedFps) {
        const auto fpsScale = float(fps - mLowFps) / (mHighFps - mLowFps);
        half4 color;
        color.r = HIGH_FPS_COLOR.r * fpsScale + LOW_FPS_COLOR.r * (1 - fpsScale);
        color.g = HIGH_FPS_COLOR.g * fpsScale + LOW_FPS_COLOR.g * (1 - fpsScale);
        color.b = HIGH_FPS_COLOR.b * fpsScale + LOW_FPS_COLOR.b * (1 - fpsScale);
        color.a = ALPHA;
        mBufferCache.emplace(fps, SevenSegmentDrawer::drawNumber(fps, color));
    }
}

void RefreshRateOverlay::setViewport(ui::Size viewport) {
    Rect frame(viewport.width >> 3, viewport.height >> 5);
    frame.offsetBy(viewport.width >> 5, viewport.height >> 4);
    mLayer->setFrame(frame);

    mFlinger.mTransactionFlags.fetch_or(eTransactionMask);
}

void RefreshRateOverlay::changeRefreshRate(const RefreshRate& refreshRate) {
    auto buffer = mBufferCache[refreshRate.getFps()];
    mLayer->setBuffer(buffer, Fence::NO_FENCE, 0, 0, {});

    mFlinger.mTransactionFlags.fetch_or(eTransactionMask);
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
