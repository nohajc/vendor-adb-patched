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
#include <android-base/stringprintf.h>
#include <cutils/compiler.h>
#include <utils/Trace.h>
#include <cmath>
#include <string>

namespace android {

template <typename T>
class TracedOrdinal {
public:
    static_assert(std::is_same<bool, T>() || (std::is_signed<T>() && std::is_integral<T>()),
                  "Type is not supported. Please test it with systrace before adding "
                  "it to the list.");

    TracedOrdinal(std::string name, T initialValue)
          : mName(std::move(name)),
            mHasGoneNegative(std::signbit(initialValue)),
            mData(initialValue) {
        trace();
    }

    operator T() const { return mData; }

    TracedOrdinal& operator=(T other) {
        mData = other;
        mHasGoneNegative = mHasGoneNegative || std::signbit(mData);
        trace();
        return *this;
    }

private:
    void trace() {
        if (CC_LIKELY(!ATRACE_ENABLED())) {
            return;
        }

        if (mNameNegative.empty()) {
            mNameNegative = base::StringPrintf("%sNegative", mName.c_str());
        }

        if (!std::signbit(mData)) {
            ATRACE_INT64(mName.c_str(), int64_t(mData));
            if (mHasGoneNegative) {
                ATRACE_INT64(mNameNegative.c_str(), 0);
            }
        } else {
            ATRACE_INT64(mNameNegative.c_str(), -int64_t(mData));
            ATRACE_INT64(mName.c_str(), 0);
        }
    }

    const std::string mName;
    std::string mNameNegative;
    bool mHasGoneNegative;
    T mData;
};

} // namespace android
