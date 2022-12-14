/*
 * Copyright 2010 The Android Open Source Project
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

#include <inttypes.h>

#define LOG_TAG "QueueBufferInputOutput"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
//#define LOG_NDEBUG 0

#include <gui/IGraphicBufferProducer.h>

namespace android {

constexpr size_t IGraphicBufferProducer::QueueBufferInput::minFlattenedSize() {
    return sizeof(timestamp) +
            sizeof(isAutoTimestamp) +
            sizeof(dataSpace) +
            sizeof(crop) +
            sizeof(scalingMode) +
            sizeof(transform) +
            sizeof(stickyTransform) +
            sizeof(getFrameTimestamps);
}

IGraphicBufferProducer::QueueBufferInput::QueueBufferInput(const Parcel& parcel) {
    parcel.read(*this);
}

size_t IGraphicBufferProducer::QueueBufferInput::getFlattenedSize() const {
    return minFlattenedSize() +
            fence->getFlattenedSize() +
            surfaceDamage.getFlattenedSize() +
            hdrMetadata.getFlattenedSize();
}

size_t IGraphicBufferProducer::QueueBufferInput::getFdCount() const {
    return fence->getFdCount();
}

status_t IGraphicBufferProducer::QueueBufferInput::flatten(
        void*& buffer, size_t& size, int*& fds, size_t& count) const
{
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::write(buffer, size, timestamp);
    FlattenableUtils::write(buffer, size, isAutoTimestamp);
    FlattenableUtils::write(buffer, size, dataSpace);
    FlattenableUtils::write(buffer, size, crop);
    FlattenableUtils::write(buffer, size, scalingMode);
    FlattenableUtils::write(buffer, size, transform);
    FlattenableUtils::write(buffer, size, stickyTransform);
    FlattenableUtils::write(buffer, size, getFrameTimestamps);

    status_t result = fence->flatten(buffer, size, fds, count);
    if (result != NO_ERROR) {
        return result;
    }
    result = surfaceDamage.flatten(buffer, size);
    if (result != NO_ERROR) {
        return result;
    }
    FlattenableUtils::advance(buffer, size, surfaceDamage.getFlattenedSize());
    return hdrMetadata.flatten(buffer, size);
}

status_t IGraphicBufferProducer::QueueBufferInput::unflatten(
        void const*& buffer, size_t& size, int const*& fds, size_t& count)
{
    if (size < minFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::read(buffer, size, timestamp);
    FlattenableUtils::read(buffer, size, isAutoTimestamp);
    FlattenableUtils::read(buffer, size, dataSpace);
    FlattenableUtils::read(buffer, size, crop);
    FlattenableUtils::read(buffer, size, scalingMode);
    FlattenableUtils::read(buffer, size, transform);
    FlattenableUtils::read(buffer, size, stickyTransform);
    FlattenableUtils::read(buffer, size, getFrameTimestamps);

    fence = new Fence();
    status_t result = fence->unflatten(buffer, size, fds, count);
    if (result != NO_ERROR) {
        return result;
    }
    result = surfaceDamage.unflatten(buffer, size);
    if (result != NO_ERROR) {
        return result;
    }
    FlattenableUtils::advance(buffer, size, surfaceDamage.getFlattenedSize());
    return hdrMetadata.unflatten(buffer, size);
}

////////////////////////////////////////////////////////////////////////
constexpr size_t IGraphicBufferProducer::QueueBufferOutput::minFlattenedSize() {
    return sizeof(width) + sizeof(height) + sizeof(transformHint) + sizeof(numPendingBuffers) +
            sizeof(nextFrameNumber) + sizeof(bufferReplaced) + sizeof(maxBufferCount);
}
size_t IGraphicBufferProducer::QueueBufferOutput::getFlattenedSize() const {
    return minFlattenedSize() + frameTimestamps.getFlattenedSize();
}

size_t IGraphicBufferProducer::QueueBufferOutput::getFdCount() const {
    return frameTimestamps.getFdCount();
}

status_t IGraphicBufferProducer::QueueBufferOutput::flatten(
        void*& buffer, size_t& size, int*& fds, size_t& count) const
{
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::write(buffer, size, width);
    FlattenableUtils::write(buffer, size, height);
    FlattenableUtils::write(buffer, size, transformHint);
    FlattenableUtils::write(buffer, size, numPendingBuffers);
    FlattenableUtils::write(buffer, size, nextFrameNumber);
    FlattenableUtils::write(buffer, size, bufferReplaced);
    FlattenableUtils::write(buffer, size, maxBufferCount);

    return frameTimestamps.flatten(buffer, size, fds, count);
}

status_t IGraphicBufferProducer::QueueBufferOutput::unflatten(
        void const*& buffer, size_t& size, int const*& fds, size_t& count)
{
    if (size < minFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::read(buffer, size, width);
    FlattenableUtils::read(buffer, size, height);
    FlattenableUtils::read(buffer, size, transformHint);
    FlattenableUtils::read(buffer, size, numPendingBuffers);
    FlattenableUtils::read(buffer, size, nextFrameNumber);
    FlattenableUtils::read(buffer, size, bufferReplaced);
    FlattenableUtils::read(buffer, size, maxBufferCount);

    return frameTimestamps.unflatten(buffer, size, fds, count);
}

} // namespace android
