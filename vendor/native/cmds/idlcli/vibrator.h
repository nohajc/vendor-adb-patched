/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <future>

#include <aidl/android/hardware/vibrator/BnVibratorCallback.h>
#include <aidl/android/hardware/vibrator/IVibrator.h>
#include <aidl/android/hardware/vibrator/IVibratorManager.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android/hardware/vibrator/1.3/IVibrator.h>

#include "IdlCli.h"
#include "utils.h"

namespace android {

using hardware::Return;
using idlcli::IdlCli;

static constexpr int NUM_TRIES = 2;

// Creates a Return<R> with STATUS::EX_NULL_POINTER.
template <class R>
inline R NullptrStatus() {
    using ::android::hardware::Status;
    return Status::fromExceptionCode(Status::EX_NULL_POINTER);
}

template <>
inline ndk::ScopedAStatus NullptrStatus() {
    return ndk::ScopedAStatus(AStatus_fromExceptionCode(EX_NULL_POINTER));
}

template <typename I>
inline auto getService(std::string name) {
    const auto instance = std::string() + I::descriptor + "/" + name;
    auto vibBinder = ndk::SpAIBinder(AServiceManager_getService(instance.c_str()));
    return I::fromBinder(vibBinder);
}

template <>
inline auto getService<android::hardware::vibrator::V1_0::IVibrator>(std::string name) {
    return android::hardware::vibrator::V1_0::IVibrator::getService(name);
}

template <>
inline auto getService<android::hardware::vibrator::V1_1::IVibrator>(std::string name) {
    return android::hardware::vibrator::V1_1::IVibrator::getService(name);
}

template <>
inline auto getService<android::hardware::vibrator::V1_2::IVibrator>(std::string name) {
    return android::hardware::vibrator::V1_2::IVibrator::getService(name);
}

template <>
inline auto getService<android::hardware::vibrator::V1_3::IVibrator>(std::string name) {
    return android::hardware::vibrator::V1_3::IVibrator::getService(name);
}

template <typename I>
using shared_ptr = std::result_of_t<decltype(getService<I>)&(std::string)>;

template <typename I>
class HalWrapper {
public:
    static std::unique_ptr<HalWrapper> Create() {
        // Assume that if getService returns a nullptr, HAL is not available on the
        // device.
        const auto name = IdlCli::Get().getName();
        auto hal = getService<I>(name.empty() ? "default" : name);
        return hal ? std::unique_ptr<HalWrapper>(new HalWrapper(std::move(hal))) : nullptr;
    }

    template <class R, class... Args0, class... Args1>
    R call(R (I::*fn)(Args0...), Args1&&... args1) {
        return (*mHal.*fn)(std::forward<Args1>(args1)...);
    }

private:
    HalWrapper(shared_ptr<I>&& hal) : mHal(std::move(hal)) {}

private:
    shared_ptr<I> mHal;
};

template <typename I>
static auto getHal() {
    static auto sHalWrapper = HalWrapper<I>::Create();
    return sHalWrapper.get();
}

template <class R, class I, class... Args0, class... Args1>
R halCall(R (I::*fn)(Args0...), Args1&&... args1) {
    auto hal = getHal<I>();
    return hal ? hal->call(fn, std::forward<Args1>(args1)...) : NullptrStatus<R>();
}

namespace idlcli {
namespace vibrator {

namespace V1_0 = ::android::hardware::vibrator::V1_0;
namespace V1_1 = ::android::hardware::vibrator::V1_1;
namespace V1_2 = ::android::hardware::vibrator::V1_2;
namespace V1_3 = ::android::hardware::vibrator::V1_3;
namespace aidl = ::aidl::android::hardware::vibrator;

class VibratorCallback : public aidl::BnVibratorCallback {
public:
    ndk::ScopedAStatus onComplete() override {
        mPromise.set_value();
        return ndk::ScopedAStatus::ok();
    }
    void waitForComplete() { mPromise.get_future().wait(); }

private:
    std::promise<void> mPromise;
};

} // namespace vibrator
} // namespace idlcli

} // namespace android
