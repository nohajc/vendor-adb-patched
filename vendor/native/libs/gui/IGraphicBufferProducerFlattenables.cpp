/*
 * Copyright 2021 The Android Open Source Project
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
            sizeof(getFrameTimestamps) +
            sizeof(slot);
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
    result = hdrMetadata.flatten(buffer, size);
    if (result != NO_ERROR) {
        return result;
    }
    FlattenableUtils::advance(buffer, size, hdrMetadata.getFlattenedSize());
    FlattenableUtils::write(buffer, size, slot);
    return NO_ERROR;
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
    result =  hdrMetadata.unflatten(buffer, size);
    if (result != NO_ERROR) {
        return result;
    }
    FlattenableUtils::advance(buffer, size, hdrMetadata.getFlattenedSize());
    FlattenableUtils::read(buffer, size, slot);
    return NO_ERROR;
}

////////////////////////////////////////////////////////////////////////
constexpr size_t IGraphicBufferProducer::QueueBufferOutput::minFlattenedSize() {
    return sizeof(width) + sizeof(height) + sizeof(transformHint) + sizeof(numPendingBuffers) +
            sizeof(nextFrameNumber) + sizeof(bufferReplaced) + sizeof(maxBufferCount) +
            sizeof(result);
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

    status_t result = frameTimestamps.flatten(buffer, size, fds, count);
    if (result != NO_ERROR) {
        return result;
    }
    FlattenableUtils::write(buffer, size, result);
    return NO_ERROR;
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

    status_t result = frameTimestamps.unflatten(buffer, size, fds, count);
    if (result != NO_ERROR) {
        return result;
    }
    FlattenableUtils::read(buffer, size, result);
    return NO_ERROR;
}

////////////////////////////////////////////////////////////////////////
constexpr size_t IGraphicBufferProducer::RequestBufferOutput::minFlattenedSize() {
    return sizeof(result) +
            sizeof(int32_t); // IsBufferNull
}

size_t IGraphicBufferProducer::RequestBufferOutput::getFlattenedSize() const {
    return minFlattenedSize() + (buffer == nullptr ? 0 : buffer->getFlattenedSize());
}

size_t IGraphicBufferProducer::RequestBufferOutput::getFdCount() const {
    return (buffer == nullptr ? 0 : buffer->getFdCount());
}

status_t IGraphicBufferProducer::RequestBufferOutput::flatten(
        void*& fBuffer, size_t& size, int*& fds, size_t& count) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::write(fBuffer, size, result);
    const int32_t isBufferNull = (buffer == nullptr ? 1 : 0);
    FlattenableUtils::write(fBuffer, size, isBufferNull);

    if (!isBufferNull) {
        status_t status = buffer->flatten(fBuffer, size, fds, count);
        if (status != NO_ERROR) {
            return status;
        }
    }
    return NO_ERROR;
}

status_t IGraphicBufferProducer::RequestBufferOutput::unflatten(
        void const*& fBuffer, size_t& size, int const*& fds, size_t& count) {
    if (size < minFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::read(fBuffer, size, result);
    int32_t isBufferNull = 0;
    FlattenableUtils::read(fBuffer, size, isBufferNull);
    buffer = new GraphicBuffer();
    if (!isBufferNull) {
        status_t status = buffer->unflatten(fBuffer, size, fds, count);
        if (status != NO_ERROR) {
            return status;
        }
    }
    return NO_ERROR;
}

////////////////////////////////////////////////////////////////////////

size_t IGraphicBufferProducer::DequeueBufferInput::getFlattenedSize() const {
    return sizeof(width) + sizeof(height) + sizeof(format) + sizeof(usage) +
            sizeof(int32_t/*getTimestamps*/);
}

status_t IGraphicBufferProducer::DequeueBufferInput::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    FlattenableUtils::write(buffer, size, width);
    FlattenableUtils::write(buffer, size, height);
    FlattenableUtils::write(buffer, size, format);
    FlattenableUtils::write(buffer, size, usage);
    const int32_t getTimestampsInt = (getTimestamps ? 1 : 0);
    FlattenableUtils::write(buffer, size, getTimestampsInt);

    return NO_ERROR;
}

status_t IGraphicBufferProducer::DequeueBufferInput::unflatten(void const* buffer, size_t size) {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::read(buffer, size, width);
    FlattenableUtils::read(buffer, size, height);
    FlattenableUtils::read(buffer, size, format);
    FlattenableUtils::read(buffer, size, usage);
    int32_t getTimestampsInt = 0;
    FlattenableUtils::read(buffer, size, getTimestampsInt);
    getTimestamps = (getTimestampsInt == 1);

    return NO_ERROR;
}

////////////////////////////////////////////////////////////////////////

constexpr size_t IGraphicBufferProducer::DequeueBufferOutput::minFlattenedSize() {
    return sizeof(result) + sizeof(slot) + sizeof(bufferAge) + sizeof(int32_t/*hasTimestamps*/);
}

size_t IGraphicBufferProducer::DequeueBufferOutput::getFlattenedSize() const {
    return minFlattenedSize() +
            fence->getFlattenedSize() +
            (timestamps.has_value() ? timestamps->getFlattenedSize() : 0);
}

size_t IGraphicBufferProducer::DequeueBufferOutput::getFdCount() const {
    return fence->getFdCount() +
            (timestamps.has_value() ? timestamps->getFdCount() : 0);
}

status_t IGraphicBufferProducer::DequeueBufferOutput::flatten(
        void*& buffer, size_t& size, int*& fds, size_t& count) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::write(buffer, size, result);
    FlattenableUtils::write(buffer, size, slot);
    FlattenableUtils::write(buffer, size, bufferAge);
    status_t status = fence->flatten(buffer, size, fds, count);
    if (status != NO_ERROR) {
        return result;
    }
    const int32_t hasTimestamps = timestamps.has_value() ? 1 : 0;
    FlattenableUtils::write(buffer, size, hasTimestamps);
    if (timestamps.has_value()) {
        status = timestamps->flatten(buffer, size, fds, count);
    }
    return status;
}

status_t IGraphicBufferProducer::DequeueBufferOutput::unflatten(
        void const*& buffer, size_t& size, int const*& fds, size_t& count) {
    if (size < minFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::read(buffer, size, result);
    FlattenableUtils::read(buffer, size, slot);
    FlattenableUtils::read(buffer, size, bufferAge);

    fence = new Fence();
    status_t status = fence->unflatten(buffer, size, fds, count);
    if (status != NO_ERROR) {
        return status;
    }
    int32_t hasTimestamps = 0;
    FlattenableUtils::read(buffer, size, hasTimestamps);
    if (hasTimestamps) {
        timestamps.emplace();
        status = timestamps->unflatten(buffer, size, fds, count);
    }
    return status;
}

////////////////////////////////////////////////////////////////////////

size_t IGraphicBufferProducer::AttachBufferOutput::getFlattenedSize() const {
    return sizeof(result) + sizeof(slot);
}

status_t IGraphicBufferProducer::AttachBufferOutput::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    FlattenableUtils::write(buffer, size, result);
    FlattenableUtils::write(buffer, size, slot);

    return NO_ERROR;
}

status_t IGraphicBufferProducer::AttachBufferOutput::unflatten(void const* buffer, size_t size) {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    FlattenableUtils::read(buffer, size, result);
    FlattenableUtils::read(buffer, size, slot);

    return NO_ERROR;
}

////////////////////////////////////////////////////////////////////////

constexpr size_t IGraphicBufferProducer::CancelBufferInput::minFlattenedSize() {
    return sizeof(slot);
}

size_t IGraphicBufferProducer::CancelBufferInput::getFlattenedSize() const {
    return minFlattenedSize() + fence->getFlattenedSize();
}

size_t IGraphicBufferProducer::CancelBufferInput::getFdCount() const {
    return fence->getFdCount();
}

status_t IGraphicBufferProducer::CancelBufferInput::flatten(
        void*& buffer, size_t& size, int*& fds, size_t& count) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::write(buffer, size, slot);
    return fence->flatten(buffer, size, fds, count);
}

status_t IGraphicBufferProducer::CancelBufferInput::unflatten(
        void const*& buffer, size_t& size, int const*& fds, size_t& count) {
    if (size < minFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::read(buffer, size, slot);

    fence = new Fence();
    return fence->unflatten(buffer, size, fds, count);
}

////////////////////////////////////////////////////////////////////////

size_t IGraphicBufferProducer::QueryOutput::getFlattenedSize() const {
    return sizeof(result) + sizeof(value);
}

status_t IGraphicBufferProducer::QueryOutput::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    FlattenableUtils::write(buffer, size, result);
    FlattenableUtils::write(buffer, size, value);

    return NO_ERROR;
}

status_t IGraphicBufferProducer::QueryOutput::unflatten(void const* buffer, size_t size) {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    FlattenableUtils::read(buffer, size, result);
    FlattenableUtils::read(buffer, size, value);

    return NO_ERROR;
}

} // namespace android
