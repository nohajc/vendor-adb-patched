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

#define LOG_TAG "IGBPBatchOps"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
//#define LOG_NDEBUG 0

#include <gui/IGraphicBufferProducer.h>

namespace android {

/**
 * Default implementation of batched buffer operations. These default
 * implementations call into the non-batched version of the same operation.
 */

status_t IGraphicBufferProducer::requestBuffers(
        const std::vector<int32_t>& slots,
        std::vector<RequestBufferOutput>* outputs) {
    outputs->clear();
    outputs->reserve(slots.size());
    for (int32_t slot : slots) {
        RequestBufferOutput& output = outputs->emplace_back();
        output.result = requestBuffer(static_cast<int>(slot),
                                      &output.buffer);
    }
    return NO_ERROR;
}

status_t IGraphicBufferProducer::dequeueBuffers(
        const std::vector<DequeueBufferInput>& inputs,
        std::vector<DequeueBufferOutput>* outputs) {
    outputs->clear();
    outputs->reserve(inputs.size());
    for (const DequeueBufferInput& input : inputs) {
        DequeueBufferOutput& output = outputs->emplace_back();
        output.result = dequeueBuffer(
                &output.slot,
                &output.fence,
                input.width,
                input.height,
                input.format,
                input.usage,
                &output.bufferAge,
                input.getTimestamps ? &output.timestamps.emplace() : nullptr);
    }
    return NO_ERROR;
}

status_t IGraphicBufferProducer::detachBuffers(
        const std::vector<int32_t>& slots,
        std::vector<status_t>* results) {
    results->clear();
    results->reserve(slots.size());
    for (int32_t slot : slots) {
        results->emplace_back(detachBuffer(slot));
    }
    return NO_ERROR;
}

status_t IGraphicBufferProducer::attachBuffers(
        const std::vector<sp<GraphicBuffer>>& buffers,
        std::vector<AttachBufferOutput>* outputs) {
    outputs->clear();
    outputs->reserve(buffers.size());
    for (const sp<GraphicBuffer>& buffer : buffers) {
        AttachBufferOutput& output = outputs->emplace_back();
        output.result = attachBuffer(&output.slot, buffer);
    }
    return NO_ERROR;
}

status_t IGraphicBufferProducer::queueBuffers(
        const std::vector<QueueBufferInput>& inputs,
        std::vector<QueueBufferOutput>* outputs) {
    outputs->clear();
    outputs->reserve(inputs.size());
    for (const QueueBufferInput& input : inputs) {
        QueueBufferOutput& output = outputs->emplace_back();
        output.result = queueBuffer(input.slot, input, &output);
    }
    return NO_ERROR;
}

status_t IGraphicBufferProducer::cancelBuffers(
        const std::vector<CancelBufferInput>& inputs,
        std::vector<status_t>* results) {
    results->clear();
    results->reserve(inputs.size());
    for (const CancelBufferInput& input : inputs) {
        results->emplace_back() = cancelBuffer(input.slot, input.fence);
    }
    return NO_ERROR;
}

status_t IGraphicBufferProducer::query(const std::vector<int32_t> inputs,
                                       std::vector<QueryOutput>* outputs) {
    outputs->clear();
    outputs->reserve(inputs.size());
    for (int32_t input : inputs) {
        QueryOutput& output = outputs->emplace_back();
        int value{};
        output.result = static_cast<status_t>(
                query(static_cast<int>(input), &value));
        output.value = static_cast<int64_t>(value);
    }
    return NO_ERROR;
}

} // namespace android
