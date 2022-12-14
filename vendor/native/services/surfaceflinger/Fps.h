/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include <ostream>
#include <string>

#include <android-base/stringprintf.h>
#include <utils/Timers.h>

namespace android {

// Value which represents "frames per second". This class is a wrapper around
// float, providing some useful utilities, such as comparisons with tolerance
// and converting between period duration and frequency.
class Fps {
public:
    static constexpr Fps fromPeriodNsecs(nsecs_t period) { return Fps(1e9f / period, period); }

    Fps() = default;
    explicit constexpr Fps(float fps)
          : fps(fps), period(fps == 0.0f ? 0 : static_cast<nsecs_t>(1e9f / fps)) {}

    constexpr float getValue() const { return fps; }

    constexpr nsecs_t getPeriodNsecs() const { return period; }

    bool equalsWithMargin(const Fps& other) const { return std::abs(fps - other.fps) < kMargin; }

    // DO NOT use for std::sort. Instead use comparesLess().
    bool lessThanWithMargin(const Fps& other) const { return fps + kMargin < other.fps; }

    bool greaterThanWithMargin(const Fps& other) const { return fps > other.fps + kMargin; }

    bool lessThanOrEqualWithMargin(const Fps& other) const { return !greaterThanWithMargin(other); }

    bool greaterThanOrEqualWithMargin(const Fps& other) const { return !lessThanWithMargin(other); }

    bool isValid() const { return fps > 0.0f; }

    int getIntValue() const { return static_cast<int>(std::round(fps)); }

    // Use this comparator for sorting. Using a comparator with margins can
    // cause std::sort to crash.
    inline static bool comparesLess(const Fps& left, const Fps& right) {
        return left.fps < right.fps;
    }

    // Compares two FPS with margin.
    // Transitivity is not guaranteed, i.e. a==b and b==c doesn't imply a==c.
    // DO NOT use with hash maps. Instead use EqualsInBuckets.
    struct EqualsWithMargin {
        bool operator()(const Fps& left, const Fps& right) const {
            return left.equalsWithMargin(right);
        }
    };

    // Equals comparator which can be used with hash maps.
    // It's guaranteed that if two elements are equal, then their hashes are equal.
    struct EqualsInBuckets {
        bool operator()(const Fps& left, const Fps& right) const {
            return left.getBucket() == right.getBucket();
        }
    };

    inline friend std::string to_string(const Fps& fps) {
        return base::StringPrintf("%.2ffps", fps.fps);
    }

    inline friend std::ostream& operator<<(std::ostream& os, const Fps& fps) {
        return os << to_string(fps);
    }

private:
    friend std::hash<android::Fps>;

    constexpr Fps(float fps, nsecs_t period) : fps(fps), period(period) {}

    float getBucket() const { return std::round(fps / kMargin); }

    static constexpr float kMargin = 0.001f;
    float fps = 0;
    nsecs_t period = 0;
};

static_assert(std::is_trivially_copyable_v<Fps>);

} // namespace android

namespace std {
template <>
struct hash<android::Fps> {
    std::size_t operator()(const android::Fps& fps) const {
        return std::hash<float>()(fps.getBucket());
    }
};
} // namespace std