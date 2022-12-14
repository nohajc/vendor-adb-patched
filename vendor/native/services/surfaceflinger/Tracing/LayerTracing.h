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

#pragma once

#include <android-base/thread_annotations.h>
#include <layerproto/LayerProtoHeader.h>
#include <utils/Errors.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

#include <memory>
#include <mutex>

using namespace android::surfaceflinger;

namespace android {

template <typename FileProto, typename EntryProto>
class RingBuffer;

class SurfaceFlinger;

/*
 * LayerTracing records layer states during surface flinging. Manages tracing state and
 * configuration.
 */
class LayerTracing {
public:
    LayerTracing(SurfaceFlinger& flinger);
    ~LayerTracing();
    bool enable();
    bool disable(std::string filename = FILE_NAME);
    bool isEnabled() const;
    status_t writeToFile();
    LayersTraceFileProto createTraceFileProto() const;
    void notify(bool visibleRegionDirty, int64_t time);

    enum : uint32_t {
        TRACE_INPUT = 1 << 1,
        TRACE_COMPOSITION = 1 << 2,
        TRACE_EXTRA = 1 << 3,
        TRACE_HWC = 1 << 4,
        TRACE_BUFFERS = 1 << 5,
        TRACE_ALL = TRACE_INPUT | TRACE_COMPOSITION | TRACE_EXTRA,
    };
    void setTraceFlags(uint32_t flags);
    bool flagIsSet(uint32_t flags) const;
    void setBufferSize(size_t bufferSizeInBytes);
    void dump(std::string&) const;

private:
    static constexpr auto FILE_NAME = "/data/misc/wmtrace/layers_trace.winscope";

    SurfaceFlinger& mFlinger;
    uint32_t mFlags = TRACE_INPUT;
    mutable std::mutex mTraceLock;
    bool mEnabled GUARDED_BY(mTraceLock) = false;
    std::unique_ptr<RingBuffer<LayersTraceFileProto, LayersTraceProto>> mBuffer
            GUARDED_BY(mTraceLock);
    size_t mBufferSizeInBytes GUARDED_BY(mTraceLock) = 20 * 1024 * 1024;
};

} // namespace android
