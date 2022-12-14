/*
 * Copyright 2020 The Android Open Source Project
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

#include <cmath>
#include <limits>
#include <ostream>
#include <string>
#include <type_traits>

#include <android-base/stringprintf.h>
#include <utils/Timers.h>

namespace android {

// Frames per second, stored as floating-point frequency. Provides conversion from/to period in
// nanoseconds, and relational operators with precision threshold.
//
//     const Fps fps = 60_Hz;
//
//     using namespace fps_approx_ops;
//     assert(fps == Fps::fromPeriodNsecs(16'666'667));
//
class Fps {
public:
    constexpr Fps() = default;

    static constexpr Fps fromValue(float frequency) {
        return frequency > 0.f ? Fps(frequency, static_cast<nsecs_t>(1e9f / frequency)) : Fps();
    }

    static constexpr Fps fromPeriodNsecs(nsecs_t period) {
        return period > 0 ? Fps(1e9f / period, period) : Fps();
    }

    constexpr bool isValid() const { return mFrequency > 0.f; }

    constexpr float getValue() const { return mFrequency; }
    int getIntValue() const { return static_cast<int>(std::round(mFrequency)); }

    constexpr nsecs_t getPeriodNsecs() const { return mPeriod; }

private:
    constexpr Fps(float frequency, nsecs_t period) : mFrequency(frequency), mPeriod(period) {}

    float mFrequency = 0.f;
    nsecs_t mPeriod = 0;
};

struct FpsRange {
    Fps min = Fps::fromValue(0.f);
    Fps max = Fps::fromValue(std::numeric_limits<float>::max());

    bool includes(Fps) const;
};

static_assert(std::is_trivially_copyable_v<Fps>);

constexpr Fps operator""_Hz(unsigned long long frequency) {
    return Fps::fromValue(static_cast<float>(frequency));
}

constexpr Fps operator""_Hz(long double frequency) {
    return Fps::fromValue(static_cast<float>(frequency));
}

inline bool isStrictlyLess(Fps lhs, Fps rhs) {
    return lhs.getValue() < rhs.getValue();
}

// Does not satisfy equivalence relation.
inline bool isApproxEqual(Fps lhs, Fps rhs) {
    // TODO(b/185536303): Replace with ULP distance.
    return std::abs(lhs.getValue() - rhs.getValue()) < 0.001f;
}

// Does not satisfy strict weak order.
inline bool isApproxLess(Fps lhs, Fps rhs) {
    return isStrictlyLess(lhs, rhs) && !isApproxEqual(lhs, rhs);
}

namespace fps_approx_ops {

inline bool operator==(Fps lhs, Fps rhs) {
    return isApproxEqual(lhs, rhs);
}

inline bool operator<(Fps lhs, Fps rhs) {
    return isApproxLess(lhs, rhs);
}

inline bool operator!=(Fps lhs, Fps rhs) {
    return !isApproxEqual(lhs, rhs);
}

inline bool operator>(Fps lhs, Fps rhs) {
    return isApproxLess(rhs, lhs);
}

inline bool operator<=(Fps lhs, Fps rhs) {
    return !isApproxLess(rhs, lhs);
}

inline bool operator>=(Fps lhs, Fps rhs) {
    return !isApproxLess(lhs, rhs);
}

inline bool operator==(FpsRange lhs, FpsRange rhs) {
    return isApproxEqual(lhs.min, rhs.min) && isApproxEqual(lhs.max, rhs.max);
}

inline bool operator!=(FpsRange lhs, FpsRange rhs) {
    return !(lhs == rhs);
}

} // namespace fps_approx_ops

inline bool FpsRange::includes(Fps fps) const {
    using fps_approx_ops::operator<=;
    return min <= fps && fps <= max;
}

struct FpsApproxEqual {
    bool operator()(Fps lhs, Fps rhs) const { return isApproxEqual(lhs, rhs); }
};

inline std::string to_string(Fps fps) {
    return base::StringPrintf("%.2f Hz", fps.getValue());
}

inline std::ostream& operator<<(std::ostream& stream, Fps fps) {
    return stream << to_string(fps);
}

inline std::string to_string(FpsRange range) {
    const auto [min, max] = range;
    return base::StringPrintf("[%s, %s]", to_string(min).c_str(), to_string(max).c_str());
}

} // namespace android
