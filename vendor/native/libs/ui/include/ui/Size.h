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

#include <algorithm>
#include <cstdint>
#include <limits>
#include <ostream>
#include <type_traits>
#include <utility>

#include <ui/Rotation.h>

namespace android::ui {

// A simple value type representing a two-dimensional size.
struct Size {
    int32_t width = -1;
    int32_t height = -1;

    constexpr Size() = default;

    template <typename T>
    constexpr Size(T w, T h) : width(clamp<int32_t>(w)), height(clamp<int32_t>(h)) {}

    int32_t getWidth() const { return width; }
    int32_t getHeight() const { return height; }

    // Valid means non-negative width and height
    bool isValid() const { return width >= 0 && height >= 0; }

    // Empty means zero width and height
    bool isEmpty() const;

    template <typename T>
    void setWidth(T v) {
        width = clamp<int32_t>(v);
    }

    template <typename T>
    void setHeight(T v) {
        height = clamp<int32_t>(v);
    }

    void set(Size size) { *this = size; }

    template <typename T>
    void set(T w, T h) {
        set(Size(w, h));
    }

    // Applies a rotation onto the size
    void rotate(Rotation rotation) {
        if (rotation == ROTATION_90 || rotation == ROTATION_270) {
            transpose();
        }
    }

    // Swaps the width and height, emulating a 90 degree rotation.
    void transpose() { std::swap(width, height); }

    // Sets the value to kInvalidSize
    void makeInvalid();

    // Sets the value to kEmptySize
    void clear();

    // TODO: Replace with std::remove_cvref_t in C++20.
    template <typename T>
    using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;

    // Takes a value of type FromType, and ensures it can be represented as a value of type ToType,
    // clamping the input value to the output range if necessary.
    template <typename ToType, typename FromType>
    static constexpr remove_cvref_t<ToType> clamp(FromType v) {
        using BareToType = remove_cvref_t<ToType>;
        using ToLimits = std::numeric_limits<BareToType>;

        using BareFromType = remove_cvref_t<FromType>;
        using FromLimits = std::numeric_limits<BareFromType>;

        static_assert(ToLimits::is_specialized && FromLimits::is_specialized);

        constexpr auto toHighest = ToLimits::max();
        constexpr auto toLowest = ToLimits::lowest();
        constexpr auto fromHighest = FromLimits::max();
        constexpr auto fromLowest = FromLimits::lowest();

        // Get the closest representation of [toLowest, toHighest] in type
        // FromType to use to clamp the input value before conversion.

        // std::common_type<...> is used to get a value-preserving type for the
        // top end of the range.
        using CommonHighestType = std::common_type_t<BareToType, BareFromType>;
        using CommonLimits = std::numeric_limits<CommonHighestType>;

        // std::make_signed<std::common_type<...>> is used to get a
        // value-preserving type for the bottom end of the range, except this is
        // a bit trickier for non-integer types like float.
        using CommonLowestType = std::conditional_t<
                CommonLimits::is_integer,
                std::make_signed_t<std::conditional_t<CommonLimits::is_integer, CommonHighestType,
                                                      int /* not used */>>,
                CommonHighestType>;

        // We can then compute the clamp range in a way that can be later
        // trivially converted to either the 'from' or 'to' types, and be
        // representable in either.
        constexpr auto commonClampHighest = std::min(static_cast<CommonHighestType>(fromHighest),
                                                     static_cast<CommonHighestType>(toHighest));
        constexpr auto commonClampLowest = std::max(static_cast<CommonLowestType>(fromLowest),
                                                    static_cast<CommonLowestType>(toLowest));

        constexpr auto fromClampHighest = static_cast<BareFromType>(commonClampHighest);
        constexpr auto fromClampLowest = static_cast<BareFromType>(commonClampLowest);

        // A clamp is needed only if the range we are clamping to is not the
        // same as the range of the input.
        constexpr bool isClampNeeded =
                (fromLowest != fromClampLowest) || (fromHighest != fromClampHighest);

        // If a clamp is not needed, the conversion is just a trivial cast.
        if constexpr (!isClampNeeded) {
            return static_cast<BareToType>(v);
        }

        // Note: Clang complains about the value of INT32_MAX not being
        // convertible back to int32_t from float if this is made "constexpr",
        // when clamping a float value to an int32_t value. This is however
        // covered by a test case to ensure the run-time cast works correctly.
        const auto toClampHighest = static_cast<BareToType>(commonClampHighest);
        const auto toClampLowest = static_cast<BareToType>(commonClampLowest);

        // Otherwise clamping is done by using the already computed endpoints
        // for each type.
        if (v <= fromClampLowest) {
            return toClampLowest;
        }

        return v >= fromClampHighest ? toClampHighest : static_cast<BareToType>(v);
    }
};

constexpr Size kInvalidSize;
constexpr Size kEmptySize{0, 0};

inline void Size::makeInvalid() {
    set(kInvalidSize);
}

inline void Size::clear() {
    set(kEmptySize);
}

inline bool operator==(Size lhs, Size rhs) {
    return lhs.width == rhs.width && lhs.height == rhs.height;
}

inline bool Size::isEmpty() const {
    return *this == kEmptySize;
}

inline bool operator!=(Size lhs, Size rhs) {
    return !(lhs == rhs);
}

inline bool operator<(Size lhs, Size rhs) {
    // Orders by increasing width, then height.
    if (lhs.width != rhs.width) return lhs.width < rhs.width;
    return lhs.height < rhs.height;
}

// Defining PrintTo helps with Google Tests.
inline void PrintTo(Size size, std::ostream* stream) {
    *stream << "Size(" << size.width << ", " << size.height << ')';
}

} // namespace android::ui
