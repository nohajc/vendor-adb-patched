/*
 *
 * Copyright 2009, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_BUFFER_ALLOCATOR_H
#define ANDROID_BUFFER_ALLOCATOR_H

#include <stdint.h>

#include <memory>
#include <string>

#include <cutils/native_handle.h>

#include <ui/PixelFormat.h>

#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/Mutex.h>
#include <utils/Singleton.h>

namespace android {

class GrallocAllocator;
class GraphicBufferMapper;

class GraphicBufferAllocator : public Singleton<GraphicBufferAllocator>
{
public:
    static inline GraphicBufferAllocator& get() { return getInstance(); }

    /**
     * Allocates and imports a gralloc buffer.
     *
     * The handle must be freed with GraphicBufferAllocator::free() when no longer needed.
     */
    status_t allocate(uint32_t w, uint32_t h, PixelFormat format, uint32_t layerCount,
                      uint64_t usage, buffer_handle_t* handle, uint32_t* stride,
                      std::string requestorName);

    /**
     * Allocates and does NOT import a gralloc buffer. Buffers cannot be used until they have
     * been imported. This function is for advanced use cases only.
     *
     * The raw native handle must be freed by calling native_handle_close() followed by
     * native_handle_delete().
     */
    status_t allocateRawHandle(uint32_t w, uint32_t h, PixelFormat format, uint32_t layerCount,
                               uint64_t usage, buffer_handle_t* handle, uint32_t* stride,
                               std::string requestorName);

    /**
     * DEPRECATED: GraphicBufferAllocator does not use the graphicBufferId.
     */
    status_t allocate(uint32_t w, uint32_t h, PixelFormat format,
            uint32_t layerCount, uint64_t usage,
            buffer_handle_t* handle, uint32_t* stride, uint64_t graphicBufferId,
            std::string requestorName);

    status_t free(buffer_handle_t handle);

    uint64_t getTotalSize() const;

    void dump(std::string& res, bool less = true) const;
    static void dumpToSystemLog(bool less = true);

protected:
    struct alloc_rec_t {
        uint32_t width;
        uint32_t height;
        uint32_t stride;
        PixelFormat format;
        uint32_t layerCount;
        uint64_t usage;
        size_t size;
        std::string requestorName;
    };

    status_t allocateHelper(uint32_t w, uint32_t h, PixelFormat format, uint32_t layerCount,
                            uint64_t usage, buffer_handle_t* handle, uint32_t* stride,
                            std::string requestorName, bool importBuffer);

    static Mutex sLock;
    static KeyedVector<buffer_handle_t, alloc_rec_t> sAllocList;

    friend class Singleton<GraphicBufferAllocator>;
    GraphicBufferAllocator();
    ~GraphicBufferAllocator();

    GraphicBufferMapper& mMapper;
    std::unique_ptr<const GrallocAllocator> mAllocator;
};

// ---------------------------------------------------------------------------
}; // namespace android

#endif // ANDROID_BUFFER_ALLOCATOR_H
