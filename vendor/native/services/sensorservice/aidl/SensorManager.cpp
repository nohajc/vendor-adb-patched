/*
 * Copyright (C) 2022 The Android Open Source Project
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

// LOG_TAG defined via build flag.
#ifndef LOG_TAG
#define LOG_TAG "AidlSensorManager"
#endif

#include "DirectReportChannel.h"
#include "EventQueue.h"
#include "SensorManagerAidl.h"
#include "utils.h"

#include <aidl/android/hardware/sensors/ISensors.h>
#include <android-base/logging.h>
#include <android/binder_ibinder.h>
#include <sched.h>

namespace android {
namespace frameworks {
namespace sensorservice {
namespace implementation {

using ::aidl::android::frameworks::sensorservice::IDirectReportChannel;
using ::aidl::android::frameworks::sensorservice::IEventQueue;
using ::aidl::android::frameworks::sensorservice::IEventQueueCallback;
using ::aidl::android::frameworks::sensorservice::ISensorManager;
using ::aidl::android::hardware::common::Ashmem;
using ::aidl::android::hardware::sensors::ISensors;
using ::aidl::android::hardware::sensors::SensorInfo;
using ::aidl::android::hardware::sensors::SensorType;
using ::android::frameworks::sensorservice::implementation::SensorManagerAidl;

static const char* POLL_THREAD_NAME = "aidl_ssvc_poll";

SensorManagerAidl::SensorManagerAidl(JavaVM* vm)
      : mLooper(new Looper(false)), mStopThread(true), mJavaVm(vm) {}
SensorManagerAidl::~SensorManagerAidl() {
    // Stops pollAll inside the thread.
    std::lock_guard<std::mutex> lock(mThreadMutex);

    mStopThread = true;
    if (mLooper != nullptr) {
        mLooper->wake();
    }
    if (mPollThread.joinable()) {
        mPollThread.join();
    }
}

ndk::ScopedAStatus createDirectChannel(::android::SensorManager& manager, size_t size, int type,
                                       const native_handle_t* handle,
                                       std::shared_ptr<IDirectReportChannel>* chan) {
    int channelId = manager.createDirectChannel(size, type, handle);
    if (channelId < 0) {
        return convertResult(channelId);
    }
    if (channelId == 0) {
        return ndk::ScopedAStatus::fromServiceSpecificError(ISensorManager::RESULT_UNKNOWN_ERROR);
    }
    *chan = ndk::SharedRefBase::make<DirectReportChannel>(manager, channelId);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus SensorManagerAidl::createAshmemDirectChannel(
        const Ashmem& in_mem, int64_t in_size,
        std::shared_ptr<IDirectReportChannel>* _aidl_return) {
    if (in_size > in_mem.size || in_size < ISensors::DIRECT_REPORT_SENSOR_EVENT_TOTAL_LENGTH) {
        return ndk::ScopedAStatus::fromServiceSpecificError(ISensorManager::RESULT_BAD_VALUE);
    }
    native_handle_t* handle = native_handle_create(1, 0);
    handle->data[0] = dup(in_mem.fd.get());

    auto status = createDirectChannel(getInternalManager(), in_size, SENSOR_DIRECT_MEM_TYPE_ASHMEM,
                                      handle, _aidl_return);
    int result = native_handle_close(handle);
    CHECK(result == 0) << "Failed to close the native_handle_t: " << result;
    result = native_handle_delete(handle);
    CHECK(result == 0) << "Failed to delete the native_handle_t: " << result;

    return status;
}

ndk::ScopedAStatus SensorManagerAidl::createGrallocDirectChannel(
        const ndk::ScopedFileDescriptor& in_mem, int64_t in_size,
        std::shared_ptr<IDirectReportChannel>* _aidl_return) {
    native_handle_t* handle = native_handle_create(1, 0);
    handle->data[0] = dup(in_mem.get());

    auto status = createDirectChannel(getInternalManager(), in_size, SENSOR_DIRECT_MEM_TYPE_GRALLOC,
                                      handle, _aidl_return);
    int result = native_handle_close(handle);
    CHECK(result == 0) << "Failed to close the native_handle_t: " << result;
    result = native_handle_delete(handle);
    CHECK(result == 0) << "Failed to delete the native_handle_t: " << result;

    return status;
}

ndk::ScopedAStatus SensorManagerAidl::createEventQueue(
        const std::shared_ptr<IEventQueueCallback>& in_callback,
        std::shared_ptr<IEventQueue>* _aidl_return) {
    if (in_callback == nullptr) {
        return ndk::ScopedAStatus::fromServiceSpecificError(ISensorManager::RESULT_BAD_VALUE);
    }

    sp<::android::Looper> looper = getLooper();
    if (looper == nullptr) {
        LOG(ERROR) << "::android::SensorManagerAidl::createEventQueue cannot initialize looper";
        return ndk::ScopedAStatus::fromServiceSpecificError(ISensorManager::RESULT_UNKNOWN_ERROR);
    }

    String8 package(String8::format("aidl_client_pid_%d", AIBinder_getCallingPid()));
    sp<::android::SensorEventQueue> internalQueue = getInternalManager().createEventQueue(package);
    if (internalQueue == nullptr) {
        LOG(ERROR) << "::android::SensorManagerAidl::createEventQueue returns nullptr.";
        return ndk::ScopedAStatus::fromServiceSpecificError(ISensorManager::RESULT_UNKNOWN_ERROR);
    }

    *_aidl_return = ndk::SharedRefBase::make<EventQueue>(in_callback, looper, internalQueue);

    return ndk::ScopedAStatus::ok();
}

SensorInfo convertSensor(Sensor src) {
    SensorInfo dst;
    dst.sensorHandle = src.getHandle();
    dst.name = src.getName();
    dst.vendor = src.getVendor();
    dst.version = src.getVersion();
    dst.type = static_cast<SensorType>(src.getType());
    dst.typeAsString = src.getStringType();
    // maxRange uses maxValue because ::android::Sensor wraps the
    // internal sensor_t in this way.
    dst.maxRange = src.getMaxValue();
    dst.resolution = src.getResolution();
    dst.power = src.getPowerUsage();
    dst.minDelayUs = src.getMinDelay();
    dst.fifoReservedEventCount = src.getFifoReservedEventCount();
    dst.fifoMaxEventCount = src.getFifoMaxEventCount();
    dst.requiredPermission = src.getRequiredPermission();
    dst.maxDelayUs = src.getMaxDelay();
    dst.flags = src.getFlags();
    return dst;
}

ndk::ScopedAStatus SensorManagerAidl::getDefaultSensor(SensorType in_type,
                                                       SensorInfo* _aidl_return) {
    ::android::Sensor const* sensor =
            getInternalManager().getDefaultSensor(static_cast<int>(in_type));
    if (!sensor) {
        return ndk::ScopedAStatus::fromServiceSpecificError(ISensorManager::RESULT_NOT_EXIST);
    }
    *_aidl_return = convertSensor(*sensor);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus SensorManagerAidl::getSensorList(std::vector<SensorInfo>* _aidl_return) {
    Sensor const* const* list;
    _aidl_return->clear();
    ssize_t count = getInternalManager().getSensorList(&list);
    if (count < 0 || list == nullptr) {
        LOG(ERROR) << "SensorMAanger::getSensorList failed with count: " << count;
        return ndk::ScopedAStatus::fromServiceSpecificError(ISensorManager::RESULT_UNKNOWN_ERROR);
    }
    _aidl_return->reserve(static_cast<size_t>(count));
    for (ssize_t i = 0; i < count; ++i) {
        _aidl_return->push_back(convertSensor(*list[i]));
    }

    return ndk::ScopedAStatus::ok();
}

::android::SensorManager& SensorManagerAidl::getInternalManager() {
    std::lock_guard<std::mutex> lock(mInternalManagerMutex);
    if (mInternalManager == nullptr) {
        mInternalManager = &::android::SensorManager::getInstanceForPackage(
                String16(ISensorManager::descriptor));
    }
    return *mInternalManager;
}

/* One global looper for all event queues created from this SensorManager. */
sp<Looper> SensorManagerAidl::getLooper() {
    std::lock_guard<std::mutex> lock(mThreadMutex);

    if (!mPollThread.joinable()) {
        // if thread not initialized, start thread
        mStopThread = false;
        std::thread pollThread{[&stopThread = mStopThread, looper = mLooper, javaVm = mJavaVm] {
            struct sched_param p = {};
            p.sched_priority = 10;
            if (sched_setscheduler(0 /* current thread*/, SCHED_FIFO, &p) != 0) {
                LOG(ERROR) << "Could not use SCHED_FIFO for looper thread: " << strerror(errno);
            }

            // set looper
            Looper::setForThread(looper);

            // Attach the thread to JavaVM so that pollAll do not crash if the thread
            // eventually calls into Java.
            JavaVMAttachArgs args{.version = JNI_VERSION_1_2,
                                  .name = POLL_THREAD_NAME,
                                  .group = nullptr};
            JNIEnv* env;
            if (javaVm->AttachCurrentThread(&env, &args) != JNI_OK) {
                LOG(FATAL) << "Cannot attach SensorManager looper thread to Java VM.";
            }

            LOG(INFO) << POLL_THREAD_NAME << " started.";
            for (;;) {
                int pollResult = looper->pollAll(-1 /* timeout */);
                if (pollResult == Looper::POLL_WAKE) {
                    if (stopThread == true) {
                        LOG(INFO) << POLL_THREAD_NAME << ": requested to stop";
                        break;
                    } else {
                        LOG(INFO) << POLL_THREAD_NAME << ": spurious wake up, back to work";
                    }
                } else {
                    LOG(ERROR) << POLL_THREAD_NAME << ": Looper::pollAll returns unexpected "
                               << pollResult;
                    break;
                }
            }

            if (javaVm->DetachCurrentThread() != JNI_OK) {
                LOG(ERROR) << "Cannot detach SensorManager looper thread from Java VM.";
            }

            LOG(INFO) << POLL_THREAD_NAME << " is terminated.";
        }};
        mPollThread = std::move(pollThread);
    }
    return mLooper;
}

} // namespace implementation
} // namespace sensorservice
} // namespace frameworks
} // namespace android
