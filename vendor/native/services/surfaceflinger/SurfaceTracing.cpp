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

#undef LOG_TAG
#define LOG_TAG "SurfaceTracing"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "SurfaceTracing.h"
#include <SurfaceFlinger.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <log/log.h>
#include <utils/SystemClock.h>
#include <utils/Trace.h>

namespace android {

SurfaceTracing::SurfaceTracing(SurfaceFlinger& flinger) : mFlinger(flinger) {}

bool SurfaceTracing::enable() {
    std::scoped_lock lock(mTraceLock);
    if (mEnabled) {
        return false;
    }

    if (flagIsSet(TRACE_SYNC)) {
        runner = std::make_unique<SurfaceTracing::Runner>(mFlinger, mConfig);
    } else {
        runner = std::make_unique<SurfaceTracing::AsyncRunner>(mFlinger, mConfig,
                                                               mFlinger.mTracingLock);
    }
    mEnabled = true;
    return true;
}

bool SurfaceTracing::disable() {
    std::scoped_lock lock(mTraceLock);
    if (!mEnabled) {
        return false;
    }
    mEnabled = false;
    runner->stop();
    return true;
}

bool SurfaceTracing::isEnabled() const {
    std::scoped_lock lock(mTraceLock);
    return mEnabled;
}

status_t SurfaceTracing::writeToFile() {
    std::scoped_lock lock(mTraceLock);
    if (!mEnabled) {
        return STATUS_OK;
    }
    return runner->writeToFile();
}

void SurfaceTracing::notify(const char* where) {
    std::scoped_lock lock(mTraceLock);
    if (mEnabled) {
        runner->notify(where);
    }
}

void SurfaceTracing::notifyLocked(const char* where) {
    std::scoped_lock lock(mTraceLock);
    if (mEnabled) {
        runner->notifyLocked(where);
    }
}

void SurfaceTracing::dump(std::string& result) const {
    std::scoped_lock lock(mTraceLock);
    base::StringAppendF(&result, "Tracing state: %s\n", mEnabled ? "enabled" : "disabled");
    if (mEnabled) {
        runner->dump(result);
    }
}

void SurfaceTracing::LayersTraceBuffer::reset(size_t newSize) {
    // use the swap trick to make sure memory is released
    std::queue<LayersTraceProto>().swap(mStorage);
    mSizeInBytes = newSize;
    mUsedInBytes = 0U;
}

void SurfaceTracing::LayersTraceBuffer::emplace(LayersTraceProto&& proto) {
    size_t protoSize = static_cast<size_t>(proto.ByteSize());
    while (mUsedInBytes + protoSize > mSizeInBytes) {
        if (mStorage.empty()) {
            return;
        }
        mUsedInBytes -= static_cast<size_t>(mStorage.front().ByteSize());
        mStorage.pop();
    }
    mUsedInBytes += protoSize;
    mStorage.emplace();
    mStorage.back().Swap(&proto);
}

void SurfaceTracing::LayersTraceBuffer::flush(LayersTraceFileProto* fileProto) {
    fileProto->mutable_entry()->Reserve(static_cast<int>(mStorage.size()));

    while (!mStorage.empty()) {
        auto entry = fileProto->add_entry();
        entry->Swap(&mStorage.front());
        mStorage.pop();
    }
}

SurfaceTracing::Runner::Runner(SurfaceFlinger& flinger, SurfaceTracing::Config& config)
      : mFlinger(flinger), mConfig(config) {
    mBuffer.setSize(mConfig.bufferSize);
}

void SurfaceTracing::Runner::notify(const char* where) {
    LayersTraceProto entry = traceLayers(where);
    mBuffer.emplace(std::move(entry));
}

status_t SurfaceTracing::Runner::stop() {
    return writeToFile();
}

LayersTraceFileProto SurfaceTracing::createLayersTraceFileProto() {
    LayersTraceFileProto fileProto;
    fileProto.set_magic_number(uint64_t(LayersTraceFileProto_MagicNumber_MAGIC_NUMBER_H) << 32 |
                               LayersTraceFileProto_MagicNumber_MAGIC_NUMBER_L);
    return fileProto;
}

status_t SurfaceTracing::Runner::writeToFile() {
    ATRACE_CALL();

    LayersTraceFileProto fileProto = createLayersTraceFileProto();
    std::string output;

    mBuffer.flush(&fileProto);
    mBuffer.reset(mConfig.bufferSize);

    if (!fileProto.SerializeToString(&output)) {
        ALOGE("Could not save the proto file! Permission denied");
        return PERMISSION_DENIED;
    }

    // -rw-r--r--
    const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!android::base::WriteStringToFile(output, DEFAULT_FILE_NAME, mode, getuid(), getgid(),
                                          true)) {
        ALOGE("Could not save the proto file! There are missing fields");
        return PERMISSION_DENIED;
    }

    return NO_ERROR;
}

LayersTraceProto SurfaceTracing::Runner::traceLayers(const char* where) {
    ATRACE_CALL();

    LayersTraceProto entry;
    entry.set_elapsed_realtime_nanos(elapsedRealtimeNano());
    entry.set_where(where);
    LayersProto layers(mFlinger.dumpDrawingStateProto(mConfig.flags));

    if (flagIsSet(SurfaceTracing::TRACE_EXTRA)) {
        mFlinger.dumpOffscreenLayersProto(layers);
    }
    entry.mutable_layers()->Swap(&layers);

    if (flagIsSet(SurfaceTracing::TRACE_HWC)) {
        std::string hwcDump;
        mFlinger.dumpHwc(hwcDump);
        entry.set_hwc_blob(hwcDump);
    }
    if (!flagIsSet(SurfaceTracing::TRACE_COMPOSITION)) {
        entry.set_excludes_composition_state(true);
    }
    entry.set_missed_entries(mMissedTraceEntries);
    mFlinger.dumpDisplayProto(entry);
    return entry;
}

void SurfaceTracing::Runner::dump(std::string& result) const {
    base::StringAppendF(&result, "  number of entries: %zu (%.2fMB / %.2fMB)\n",
                        mBuffer.frameCount(), float(mBuffer.used()) / float(1_MB),
                        float(mBuffer.size()) / float(1_MB));
}

SurfaceTracing::AsyncRunner::AsyncRunner(SurfaceFlinger& flinger, SurfaceTracing::Config& config,
                                         std::mutex& sfLock)
      : SurfaceTracing::Runner(flinger, config), mSfLock(sfLock) {
    mEnabled = true;
    mThread = std::thread(&AsyncRunner::loop, this);
}

void SurfaceTracing::AsyncRunner::loop() {
    while (mEnabled) {
        LayersTraceProto entry;
        bool entryAdded = traceWhenNotified(&entry);
        if (entryAdded) {
            mBuffer.emplace(std::move(entry));
        }
        if (mWriteToFile) {
            Runner::writeToFile();
            mWriteToFile = false;
        }
    }
}

bool SurfaceTracing::AsyncRunner::traceWhenNotified(LayersTraceProto* outProto) {
    std::unique_lock<std::mutex> lock(mSfLock);
    mCanStartTrace.wait(lock);
    if (!mAddEntry) {
        return false;
    }
    *outProto = traceLayers(mWhere);
    mAddEntry = false;
    mMissedTraceEntries = 0;
    return true;
}

void SurfaceTracing::AsyncRunner::notify(const char* where) {
    std::scoped_lock lock(mSfLock);
    notifyLocked(where);
}

void SurfaceTracing::AsyncRunner::notifyLocked(const char* where) {
    mWhere = where;
    if (mAddEntry) {
        mMissedTraceEntries++;
    }
    mAddEntry = true;
    mCanStartTrace.notify_one();
}

status_t SurfaceTracing::AsyncRunner::writeToFile() {
    mWriteToFile = true;
    mCanStartTrace.notify_one();
    return STATUS_OK;
}

status_t SurfaceTracing::AsyncRunner::stop() {
    mEnabled = false;
    mCanStartTrace.notify_one();
    mThread.join();
    return Runner::writeToFile();
}

} // namespace android
