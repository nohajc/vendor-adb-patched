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

#include <numeric>
#include <optional>
#include <type_traits>
#include <vector>

#include <utils/Flattenable.h>

#define RETURN_IF_ERROR(op) \
    if (const status_t status = (op); status != OK) return status;

namespace android {

struct FlattenableHelpers {
    // Helpers for reading and writing POD structures which are not LightFlattenable.
    template <class T,
              typename = std::enable_if_t<
                      std::conjunction_v<std::is_trivially_copyable<T>,
                                         std::negation<std::is_base_of<LightFlattenable<T>, T>>>>>
    static constexpr size_t getFlattenedSize(const T&) {
        return sizeof(T);
    }

    template <class T,
              typename = std::enable_if_t<
                      std::conjunction_v<std::is_trivially_copyable<T>,
                                         std::negation<std::is_base_of<LightFlattenable<T>, T>>>>>
    static status_t flatten(void** buffer, size_t* size, const T& value) {
        if (*size < sizeof(T)) return NO_MEMORY;
        FlattenableUtils::write(*buffer, *size, value);
        return OK;
    }

    template <class T,
              typename = std::enable_if_t<
                      std::conjunction_v<std::is_trivially_copyable<T>,
                                         std::negation<std::is_base_of<LightFlattenable<T>, T>>>>>
    static status_t unflatten(const void** buffer, size_t* size, T* value) {
        if (*size < sizeof(T)) return NO_MEMORY;
        FlattenableUtils::read(*buffer, *size, *value);
        return OK;
    }

    // Helpers for reading and writing std::string
    static size_t getFlattenedSize(const std::string& str) {
        return sizeof(uint64_t) + str.length();
    }

    static status_t flatten(void** buffer, size_t* size, const std::string& str) {
        if (*size < getFlattenedSize(str)) return NO_MEMORY;
        flatten(buffer, size, (uint64_t)str.length());
        memcpy(reinterpret_cast<char*>(*buffer), str.c_str(), str.length());
        FlattenableUtils::advance(*buffer, *size, str.length());
        return OK;
    }

    static status_t unflatten(const void** buffer, size_t* size, std::string* str) {
        uint64_t length;
        RETURN_IF_ERROR(unflatten(buffer, size, &length));
        if (*size < length) return NO_MEMORY;
        str->assign(reinterpret_cast<const char*>(*buffer), length);
        FlattenableUtils::advance(*buffer, *size, length);
        return OK;
    }

    // Helpers for reading and writing LightFlattenable
    template <class T>
    static size_t getFlattenedSize(const LightFlattenable<T>& value) {
        return value.getFlattenedSize();
    }

    template <class T>
    static status_t flatten(void** buffer, size_t* size, const LightFlattenable<T>& value) {
        RETURN_IF_ERROR(value.flatten(*buffer, *size));
        FlattenableUtils::advance(*buffer, *size, value.getFlattenedSize());
        return OK;
    }

    template <class T>
    static status_t unflatten(const void** buffer, size_t* size, LightFlattenable<T>* value) {
        RETURN_IF_ERROR(value->unflatten(*buffer, *size));
        FlattenableUtils::advance(*buffer, *size, value->getFlattenedSize());
        return OK;
    }

    // Helpers for reading and writing std::optional
    template <class T, typename = std::enable_if_t<std::negation_v<std::is_trivially_copyable<T>>>>
    static size_t getFlattenedSize(const std::optional<T>& value) {
        return sizeof(bool) + (value ? getFlattenedSize(*value) : 0);
    }

    template <class T, typename = std::enable_if_t<std::negation_v<std::is_trivially_copyable<T>>>>
    static status_t flatten(void** buffer, size_t* size, const std::optional<T>& value) {
        if (value) {
            RETURN_IF_ERROR(flatten(buffer, size, true));
            RETURN_IF_ERROR(flatten(buffer, size, *value));
        } else {
            RETURN_IF_ERROR(flatten(buffer, size, false));
        }
        return OK;
    }

    template <class T, typename = std::enable_if_t<std::negation_v<std::is_trivially_copyable<T>>>>
    static status_t unflatten(const void** buffer, size_t* size, std::optional<T>* value) {
        bool isPresent;
        RETURN_IF_ERROR(unflatten(buffer, size, &isPresent));
        if (isPresent) {
            *value = T();
            RETURN_IF_ERROR(unflatten(buffer, size, &(**value)));
        } else {
            value->reset();
        }
        return OK;
    }

    // Helpers for reading and writing std::vector
    template <class T>
    static size_t getFlattenedSize(const std::vector<T>& value) {
        return std::accumulate(value.begin(), value.end(), sizeof(uint64_t),
                               [](size_t sum, const T& element) {
                                   return sum + getFlattenedSize(element);
                               });
    }

    template <class T>
    static status_t flatten(void** buffer, size_t* size, const std::vector<T>& value) {
        RETURN_IF_ERROR(flatten(buffer, size, (uint64_t)value.size()));
        for (const auto& element : value) {
            RETURN_IF_ERROR(flatten(buffer, size, element));
        }
        return OK;
    }

    template <class T>
    static status_t unflatten(const void** buffer, size_t* size, std::vector<T>* value) {
        uint64_t numElements;
        RETURN_IF_ERROR(unflatten(buffer, size, &numElements));
        // We don't need an extra size check since each iteration of the loop does that
        std::vector<T> elements;
        for (size_t i = 0; i < numElements; i++) {
            T element;
            RETURN_IF_ERROR(unflatten(buffer, size, &element));
            elements.push_back(element);
        }
        *value = std::move(elements);
        return OK;
    }
};

} // namespace android

#undef RETURN_IF_ERROR