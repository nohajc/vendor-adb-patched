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
#ifndef FRAMEWORK_NATIVE_CMDS_IDLCLI_VIBRATOR_H_
#define FRAMEWORK_NATIVE_CMDS_IDLCLI_VIBRATOR_H_

#include <aidl/android/hardware/vibrator/IVibrator.h>
#include <android/binder_manager.h>
#include <android/hardware/vibrator/1.3/IVibrator.h>

#include "utils.h"

#include "log/log.h"

namespace android {

using hardware::Return;

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
inline auto getService() {
    return I::getService();
}

template <>
inline auto getService<aidl::android::hardware::vibrator::IVibrator>() {
    const auto instance =
            std::string() + aidl::android::hardware::vibrator::IVibrator::descriptor + "/default";
    auto vibBinder = ndk::SpAIBinder(AServiceManager_getService(instance.c_str()));
    return aidl::android::hardware::vibrator::IVibrator::fromBinder(vibBinder);
}

template <typename I>
using shared_ptr = std::result_of_t<decltype(getService<I>)&()>;

template <typename I>
class HalWrapper {
public:
    static std::unique_ptr<HalWrapper> Create() {
        // Assume that if getService returns a nullptr, HAL is not available on the
        // device.
        auto hal = getService<I>();
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

} // namespace vibrator
} // namespace idlcli

} // namespace android

#endif // FRAMEWORK_NATIVE_CMDS_IDLCLI_VIBRATOR_H_
