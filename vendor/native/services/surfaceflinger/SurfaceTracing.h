/*
 * Copyright 2017 The Android Open Source Project
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

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>

using namespace android::surfaceflinger;

namespace android {

class SurfaceFlinger;

constexpr auto operator""_MB(unsigned long long const num) {
    return num * 1024 * 1024;
}
/*
 * SurfaceTracing records layer states during surface flinging.
 */
class SurfaceTracing {
public:
    explicit SurfaceTracing(SurfaceFlinger& flinger);
    bool enable();
    bool disable();
    status_t writeToFile();
    bool isEnabled() const;
    void notify(const char* where);
    void notifyLocked(const char* where) NO_THREAD_SAFETY_ANALYSIS /* REQUIRES(mSfLock) */;

    void setBufferSize(size_t bufferSizeInByte);
    void writeToFileAsync();
    void dump(std::string& result) const;

    enum : uint32_t {
        TRACE_CRITICAL = 1 << 0,
        TRACE_INPUT = 1 << 1,
        TRACE_COMPOSITION = 1 << 2,
        TRACE_EXTRA = 1 << 3,
        TRACE_HWC = 1 << 4,
        TRACE_ALL = 0xffffffff
    };
    void setTraceFlags(uint32_t flags);
    bool flagIsSetLocked(uint32_t flags) NO_THREAD_SAFETY_ANALYSIS /* REQUIRES(mSfLock) */ {
        return (mTraceFlags & flags) == flags;
    }

private:
    static constexpr auto kDefaultBufferCapInByte = 5_MB;
    static constexpr auto kDefaultFileName = "/data/misc/wmtrace/layers_trace.pb";

    class LayersTraceBuffer { // ring buffer
    public:
        size_t size() const { return mSizeInBytes; }
        size_t used() const { return mUsedInBytes; }
        size_t frameCount() const { return mStorage.size(); }

        void setSize(size_t newSize) { mSizeInBytes = newSize; }
        void reset(size_t newSize);
        void emplace(LayersTraceProto&& proto);
        void flush(LayersTraceFileProto* fileProto);

    private:
        size_t mUsedInBytes = 0U;
        size_t mSizeInBytes = 0U;
        std::queue<LayersTraceProto> mStorage;
    };

    void mainLoop();
    bool addFirstEntry();
    LayersTraceProto traceWhenNotified();
    LayersTraceProto traceLayersLocked(const char* where) REQUIRES(mSfLock);

    // Returns true if trace is enabled.
    bool addTraceToBuffer(LayersTraceProto& entry);
    void writeProtoFileLocked() REQUIRES(mTraceLock);

    SurfaceFlinger& mFlinger;
    status_t mLastErr = NO_ERROR;
    std::thread mThread;
    std::condition_variable mCanStartTrace;

    std::mutex& mSfLock;
    uint32_t mTraceFlags GUARDED_BY(mSfLock) = TRACE_CRITICAL | TRACE_INPUT;
    const char* mWhere GUARDED_BY(mSfLock) = "";
    uint32_t mMissedTraceEntries GUARDED_BY(mSfLock) = 0;
    bool mTracingInProgress GUARDED_BY(mSfLock) = false;

    mutable std::mutex mTraceLock;
    LayersTraceBuffer mBuffer GUARDED_BY(mTraceLock);
    size_t mBufferSize GUARDED_BY(mTraceLock) = kDefaultBufferCapInByte;
    bool mEnabled GUARDED_BY(mTraceLock) = false;
    bool mWriteToFile GUARDED_BY(mTraceLock) = false;
};

} // namespace android
