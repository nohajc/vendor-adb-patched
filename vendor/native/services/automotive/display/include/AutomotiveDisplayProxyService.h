//
// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#pragma once

#include <android/frameworks/automotive/display/1.0/IAutomotiveDisplayProxyService.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/ISurfaceComposer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <ui/DisplayMode.h>
#include <ui/DisplayState.h>
#include <tuple>
#include <vector>

namespace android {
namespace frameworks {
namespace automotive {
namespace display {
namespace V1_0 {
namespace implementation {

using ::android::hardware::Return;
using ::android::hardware::graphics::bufferqueue::V2_0::IGraphicBufferProducer;
using ::android::sp;


typedef struct DisplayDesc {
    sp<IBinder>        token;
    sp<SurfaceControl> surfaceControl;
} DisplayDesc;


class AutomotiveDisplayProxyService : public IAutomotiveDisplayProxyService {
public:
    Return<sp<IGraphicBufferProducer>> getIGraphicBufferProducer(uint64_t id) override;
    Return<bool> showWindow(uint64_t id) override;
    Return<bool> hideWindow(uint64_t id) override;
    Return<void> getDisplayIdList(getDisplayIdList_cb _cb) override;
    Return<void> getDisplayInfo(uint64_t, getDisplayInfo_cb _cb) override;

private:
    uint8_t getDisplayPort(const uint64_t id) { return (id & 0xF); }

    std::unordered_map<uint64_t, DisplayDesc> mDisplays;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace display
}  // namespace automotive
}  // namespace frameworks
}  // namespace android

