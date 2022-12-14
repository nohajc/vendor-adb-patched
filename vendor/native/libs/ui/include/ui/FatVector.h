/*
 * Copyright 2019, The Android Open Source Project
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

#ifndef ANDROID_REGION_FAT_VECTOR_H
#define ANDROID_REGION_FAT_VECTOR_H

#include <stddef.h>
#include <stdlib.h>
#include <utils/Log.h>
#include <type_traits>

#include <vector>

namespace android {

template <typename T, size_t SIZE = 4>
class InlineStdAllocator {
public:
    struct Allocation {
    private:
        Allocation(const Allocation&) = delete;
        void operator=(const Allocation&) = delete;

    public:
        Allocation() {}
        // char array instead of T array, so memory is uninitialized, with no destructors run
        char array[sizeof(T) * SIZE];
        bool inUse = false;
    };

    typedef T value_type; // needed to implement std::allocator
    typedef T* pointer;   // needed to implement std::allocator

    explicit InlineStdAllocator(Allocation& allocation) : mAllocation(allocation) {}
    InlineStdAllocator(const InlineStdAllocator& other) : mAllocation(other.mAllocation) {}
    ~InlineStdAllocator() {}

    T* allocate(size_t num, const void* = 0) {
        if (!mAllocation.inUse && num <= SIZE) {
            mAllocation.inUse = true;
            return static_cast<T*>(static_cast<void*>(mAllocation.array));
        } else {
            return static_cast<T*>(static_cast<void*>(malloc(num * sizeof(T))));
        }
    }

    void deallocate(pointer p, size_t) {
        if (p == static_cast<T*>(static_cast<void*>(mAllocation.array))) {
            mAllocation.inUse = false;
        } else {
            // 'free' instead of delete here - destruction handled separately
            free(p);
        }
    }
    Allocation& mAllocation;
};

/**
 * std::vector with SIZE elements preallocated into an internal buffer.
 *
 * Useful for avoiding the cost of malloc in cases where only SIZE or
 * fewer elements are needed in the common case.
 */
template <typename T, size_t SIZE = 4>
class FatVector : public std::vector<T, InlineStdAllocator<T, SIZE>> {
public:
    FatVector()
          : std::vector<T, InlineStdAllocator<T, SIZE>>(InlineStdAllocator<T, SIZE>(mAllocation)) {
        this->reserve(SIZE);
    }

    FatVector(std::initializer_list<T> init)
          : std::vector<T, InlineStdAllocator<T, SIZE>>(init,
                                                        InlineStdAllocator<T, SIZE>(mAllocation)) {
        this->reserve(SIZE);
    }

    explicit FatVector(size_t capacity) : FatVector() { this->resize(capacity); }

private:
    typename InlineStdAllocator<T, SIZE>::Allocation mAllocation;
};

} // namespace android

#endif // ANDROID_REGION_FAT_VECTOR_H
