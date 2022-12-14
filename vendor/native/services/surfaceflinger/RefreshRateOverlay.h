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

#pragma once

#include <unordered_map>

#include <math/vec4.h>
#include <ui/Rect.h>
#include <ui/Size.h>
#include <utils/StrongPointer.h>

#include "Scheduler/RefreshRateConfigs.h"

namespace android {

class Client;
class GraphicBuffer;
class IBinder;
class IGraphicBufferProducer;
class Layer;
class SurfaceFlinger;

using RefreshRate = scheduler::RefreshRateConfigs::RefreshRate;

class RefreshRateOverlay {
public:
    explicit RefreshRateOverlay(SurfaceFlinger&);

    void setViewport(ui::Size);
    void changeRefreshRate(const RefreshRate&);

private:
    class SevenSegmentDrawer {
    public:
        static sp<GraphicBuffer> drawNumber(int number, const half4& color);
        static uint32_t getHeight() { return BUFFER_HEIGHT; }
        static uint32_t getWidth() { return BUFFER_WIDTH; }

    private:
        enum class Segment { Upper, UpperLeft, UpperRight, Middle, LowerLeft, LowerRight, Buttom };

        static void drawRect(const Rect& r, const half4& color, const sp<GraphicBuffer>& buffer,
                             uint8_t* pixels);
        static void drawSegment(Segment segment, int left, const half4& color,
                                const sp<GraphicBuffer>& buffer, uint8_t* pixels);
        static void drawDigit(int digit, int left, const half4& color,
                              const sp<GraphicBuffer>& buffer, uint8_t* pixels);

        static constexpr uint32_t DIGIT_HEIGHT = 100;
        static constexpr uint32_t DIGIT_WIDTH = 64;
        static constexpr uint32_t DIGIT_SPACE = 16;
        static constexpr uint32_t BUFFER_HEIGHT = DIGIT_HEIGHT;
        static constexpr uint32_t BUFFER_WIDTH =
                3 * DIGIT_WIDTH + 2 * DIGIT_SPACE; // Digit|Space|Digit|Space|Digit
    };

    bool createLayer();
    void primeCache();

    SurfaceFlinger& mFlinger;
    const sp<Client> mClient;
    sp<Layer> mLayer;
    sp<IBinder> mIBinder;
    sp<IGraphicBufferProducer> mGbp;

    std::unordered_map<int, sp<GraphicBuffer>> mBufferCache;

    static constexpr float ALPHA = 0.8f;
    const half3 LOW_FPS_COLOR = half3(1.0f, 0.0f, 0.0f);
    const half3 HIGH_FPS_COLOR = half3(0.0f, 1.0f, 0.0f);
};

} // namespace android
