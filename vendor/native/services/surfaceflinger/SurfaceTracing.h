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
 * SurfaceTracing records layer states during surface flinging. Manages tracing state and
 * configuration.
 */
class SurfaceTracing {
public:
    SurfaceTracing(SurfaceFlinger& flinger);
    bool enable();
    bool disable();
    status_t writeToFile();
    bool isEnabled() const;
    /*
     * Adds a trace entry, must be called from the drawing thread or while holding the
     * SurfaceFlinger tracing lock.
     */
    void notify(const char* where);
    /*
     * Adds a trace entry, called while holding the SurfaceFlinger tracing lock.
     */
    void notifyLocked(const char* where) /* REQUIRES(mSfLock) */;

    void setBufferSize(size_t bufferSizeInBytes) { mConfig.bufferSize = bufferSizeInBytes; }
    void dump(std::string& result) const;

    enum : uint32_t {
        TRACE_CRITICAL = 1 << 0,
        TRACE_INPUT = 1 << 1,
        TRACE_COMPOSITION = 1 << 2,
        TRACE_EXTRA = 1 << 3,
        TRACE_HWC = 1 << 4,
        // Add non-geometry composition changes to the trace.
        TRACE_BUFFERS = 1 << 5,
        // Add entries from the drawing thread post composition.
        TRACE_SYNC = 1 << 6,
        TRACE_ALL = TRACE_CRITICAL | TRACE_INPUT | TRACE_COMPOSITION | TRACE_EXTRA,
    };
    void setTraceFlags(uint32_t flags) { mConfig.flags = flags; }
    bool flagIsSet(uint32_t flags) { return (mConfig.flags & flags) == flags; }
    static LayersTraceFileProto createLayersTraceFileProto();

private:
    class Runner;
    static constexpr auto DEFAULT_BUFFER_SIZE = 5_MB;
    static constexpr auto DEFAULT_FILE_NAME = "/data/misc/wmtrace/layers_trace.winscope";

    SurfaceFlinger& mFlinger;
    mutable std::mutex mTraceLock;
    bool mEnabled GUARDED_BY(mTraceLock) = false;
    std::unique_ptr<Runner> runner GUARDED_BY(mTraceLock);

    struct Config {
        uint32_t flags = TRACE_CRITICAL | TRACE_INPUT | TRACE_SYNC;
        size_t bufferSize = DEFAULT_BUFFER_SIZE;
    } mConfig;

    /*
     * ring buffer.
     */
    class LayersTraceBuffer {
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
        size_t mSizeInBytes = DEFAULT_BUFFER_SIZE;
        std::queue<LayersTraceProto> mStorage;
    };

    /*
     * Implements a synchronous way of adding trace entries. This must be called
     * from the drawing thread.
     */
    class Runner {
    public:
        Runner(SurfaceFlinger& flinger, SurfaceTracing::Config& config);
        virtual ~Runner() = default;
        virtual status_t stop();
        virtual status_t writeToFile();
        virtual void notify(const char* where);
        /* Cannot be called with a synchronous runner. */
        virtual void notifyLocked(const char* /* where */) {}
        void dump(std::string& result) const;

    protected:
        bool flagIsSet(uint32_t flags) { return (mConfig.flags & flags) == flags; }
        SurfaceFlinger& mFlinger;
        SurfaceTracing::Config mConfig;
        SurfaceTracing::LayersTraceBuffer mBuffer;
        uint32_t mMissedTraceEntries = 0;
        LayersTraceProto traceLayers(const char* where);
    };

    /*
     * Implements asynchronous way to add trace entries called from a separate thread while holding
     * the SurfaceFlinger tracing lock. Trace entries may be missed if the tracing thread is not
     * scheduled in time.
     */
    class AsyncRunner : public Runner {
    public:
        AsyncRunner(SurfaceFlinger& flinger, SurfaceTracing::Config& config, std::mutex& sfLock);
        virtual ~AsyncRunner() = default;
        status_t stop() override;
        status_t writeToFile() override;
        void notify(const char* where) override;
        void notifyLocked(const char* where);

    private:
        std::mutex& mSfLock;
        std::condition_variable mCanStartTrace;
        std::thread mThread;
        const char* mWhere = "";
        bool mWriteToFile = false;
        bool mEnabled = false;
        bool mAddEntry = false;
        void loop();
        bool traceWhenNotified(LayersTraceProto* outProto);
    };
};

} // namespace android
