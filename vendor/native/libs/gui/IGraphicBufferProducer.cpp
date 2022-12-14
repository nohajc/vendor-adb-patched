/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <stdint.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/NativeHandle.h>
#include <utils/RefBase.h>
#include <utils/String8.h>
#include <utils/Timers.h>
#include <utils/Vector.h>

#include <binder/Parcel.h>
#include <binder/IInterface.h>

#include <gui/bufferqueue/1.0/H2BGraphicBufferProducer.h>
#include <gui/bufferqueue/2.0/H2BGraphicBufferProducer.h>
#include <gui/BufferQueueDefs.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/IProducerListener.h>

namespace android {
// ----------------------------------------------------------------------------

using H2BGraphicBufferProducerV1_0 =
        ::android::hardware::graphics::bufferqueue::V1_0::utils::
        H2BGraphicBufferProducer;
using H2BGraphicBufferProducerV2_0 =
        ::android::hardware::graphics::bufferqueue::V2_0::utils::
        H2BGraphicBufferProducer;

enum {
    REQUEST_BUFFER = IBinder::FIRST_CALL_TRANSACTION,
    DEQUEUE_BUFFER,
    DETACH_BUFFER,
    DETACH_NEXT_BUFFER,
    ATTACH_BUFFER,
    QUEUE_BUFFER,
    CANCEL_BUFFER,
    QUERY,
    CONNECT,
    DISCONNECT,
    SET_SIDEBAND_STREAM,
    ALLOCATE_BUFFERS,
    ALLOW_ALLOCATION,
    SET_GENERATION_NUMBER,
    GET_CONSUMER_NAME,
    SET_MAX_DEQUEUED_BUFFER_COUNT,
    SET_ASYNC_MODE,
    SET_SHARED_BUFFER_MODE,
    SET_AUTO_REFRESH,
    SET_DEQUEUE_TIMEOUT,
    GET_LAST_QUEUED_BUFFER,
    GET_FRAME_TIMESTAMPS,
    GET_UNIQUE_ID,
    GET_CONSUMER_USAGE,
    SET_LEGACY_BUFFER_DROP,
    SET_AUTO_PREROTATION,
    REQUEST_BUFFERS,
    DEQUEUE_BUFFERS,
    DETACH_BUFFERS,
    ATTACH_BUFFERS,
    QUEUE_BUFFERS,
    CANCEL_BUFFERS,
    QUERY_MULTIPLE,
    GET_LAST_QUEUED_BUFFER2,
};

class BpGraphicBufferProducer : public BpInterface<IGraphicBufferProducer>
{
public:
    explicit BpGraphicBufferProducer(const sp<IBinder>& impl)
        : BpInterface<IGraphicBufferProducer>(impl)
    {
    }

    ~BpGraphicBufferProducer() override;

    virtual status_t requestBuffer(int bufferIdx, sp<GraphicBuffer>* buf) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(bufferIdx);
        status_t result = remote()->transact(REQUEST_BUFFER, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        bool nonNull = reply.readInt32();
        if (nonNull) {
            *buf = new GraphicBuffer();
            result = reply.read(**buf);
            if(result != NO_ERROR) {
                (*buf).clear();
                return result;
            }
        }
        result = reply.readInt32();
        return result;
    }

    virtual status_t requestBuffers(
            const std::vector<int32_t>& slots,
            std::vector<RequestBufferOutput>* outputs) override {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32Vector(slots);
        status_t result = remote()->transact(REQUEST_BUFFERS, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.resizeOutVector(outputs);
        for (RequestBufferOutput& output : *outputs) {
            if (result != NO_ERROR) {
                return result;
            }
            result = reply.read(output);
        }

        return result;
    }

    virtual status_t setMaxDequeuedBufferCount(int maxDequeuedBuffers) {
        Parcel data, reply;
        data.writeInterfaceToken(
                IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(maxDequeuedBuffers);
        status_t result = remote()->transact(SET_MAX_DEQUEUED_BUFFER_COUNT,
                data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readInt32();
        return result;
    }

    virtual status_t setAsyncMode(bool async) {
        Parcel data, reply;
        data.writeInterfaceToken(
                IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(async);
        status_t result = remote()->transact(SET_ASYNC_MODE,
                data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readInt32();
        return result;
    }

    virtual status_t dequeueBuffer(int* buf, sp<Fence>* fence, uint32_t width, uint32_t height,
                                   PixelFormat format, uint64_t usage, uint64_t* outBufferAge,
                                   FrameEventHistoryDelta* outTimestamps) {
        Parcel data, reply;
        bool getFrameTimestamps = (outTimestamps != nullptr);

        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeUint32(width);
        data.writeUint32(height);
        data.writeInt32(static_cast<int32_t>(format));
        data.writeUint64(usage);
        data.writeBool(getFrameTimestamps);

        status_t result = remote()->transact(DEQUEUE_BUFFER, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }

        *buf = reply.readInt32();
        *fence = new Fence();
        result = reply.read(**fence);
        if (result != NO_ERROR) {
            fence->clear();
            return result;
        }
        if (outBufferAge) {
            result = reply.readUint64(outBufferAge);
        } else {
            // Read the value even if outBufferAge is nullptr:
            uint64_t bufferAge;
            result = reply.readUint64(&bufferAge);
        }
        if (result != NO_ERROR) {
            ALOGE("IGBP::dequeueBuffer failed to read buffer age: %d", result);
            return result;
        }
        if (getFrameTimestamps) {
            result = reply.read(*outTimestamps);
            if (result != NO_ERROR) {
                ALOGE("IGBP::dequeueBuffer failed to read timestamps: %d",
                        result);
                return result;
            }
        }
        result = reply.readInt32();
        return result;
    }

    virtual status_t dequeueBuffers(
            const std::vector<DequeueBufferInput>& inputs,
            std::vector<DequeueBufferOutput>* outputs) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeVectorSize(inputs);
        for (const auto& input : inputs) {
            data.write(input);
        }
        status_t result = remote()->transact(DEQUEUE_BUFFERS, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.resizeOutVector(outputs);
        for (auto& output : *outputs) {
            if (result != NO_ERROR) {
                return result;
            }
            result = reply.read(output);
        }
        return result;
    }

    virtual status_t detachBuffer(int slot) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(slot);
        status_t result = remote()->transact(DETACH_BUFFER, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readInt32();
        return result;
    }

    virtual status_t detachBuffers(const std::vector<int32_t>& slots,
                                   std::vector<status_t>* results) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32Vector(slots);
        status_t result = remote()->transact(DETACH_BUFFERS, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readInt32Vector(results);
        return result;
    }

    virtual status_t detachNextBuffer(sp<GraphicBuffer>* outBuffer,
            sp<Fence>* outFence) {
        if (outBuffer == nullptr) {
            ALOGE("detachNextBuffer: outBuffer must not be NULL");
            return BAD_VALUE;
        } else if (outFence == nullptr) {
            ALOGE("detachNextBuffer: outFence must not be NULL");
            return BAD_VALUE;
        }
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        status_t result = remote()->transact(DETACH_NEXT_BUFFER, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readInt32();
        if (result == NO_ERROR) {
            bool nonNull = reply.readInt32();
            if (nonNull) {
                *outBuffer = new GraphicBuffer;
                result = reply.read(**outBuffer);
                if (result != NO_ERROR) {
                    outBuffer->clear();
                    return result;
                }
            }
            nonNull = reply.readInt32();
            if (nonNull) {
                *outFence = new Fence;
                result = reply.read(**outFence);
                if (result != NO_ERROR) {
                    outBuffer->clear();
                    outFence->clear();
                    return result;
                }
            }
        }
        return result;
    }

    virtual status_t attachBuffer(int* slot, const sp<GraphicBuffer>& buffer) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.write(*buffer.get());
        status_t result = remote()->transact(ATTACH_BUFFER, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }

        *slot = reply.readInt32();
        result = reply.readInt32();
        if (result == NO_ERROR &&
                (*slot < 0 || *slot >= BufferQueueDefs::NUM_BUFFER_SLOTS)) {
            ALOGE("attachBuffer returned invalid slot %d", *slot);
            android_errorWriteLog(0x534e4554, "37478824");
            return UNKNOWN_ERROR;
        }

        return result;
    }

    virtual status_t attachBuffers(
            const std::vector<sp<GraphicBuffer>>& buffers,
            std::vector<AttachBufferOutput>* outputs) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeVectorSize(buffers);
        for (const sp<GraphicBuffer>& buffer : buffers) {
            data.write(*buffer.get());
        }
        status_t result = remote()->transact(ATTACH_BUFFERS, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.resizeOutVector(outputs);
        for (AttachBufferOutput& output : *outputs) {
            if (result != NO_ERROR) {
                return result;
            }
            result = reply.read(output);
        }
        if (result == NO_ERROR) {
            for (AttachBufferOutput& output : *outputs) {
                if (output.result == NO_ERROR && output.slot < 0) {
                    ALOGE("attachBuffers returned invalid slot %d",
                          output.slot);
                    android_errorWriteLog(0x534e4554, "37478824");
                    output.result = UNKNOWN_ERROR;
                }
            }
        }
        return result;
    }

    virtual status_t queueBuffer(int buf,
            const QueueBufferInput& input, QueueBufferOutput* output) {
        Parcel data, reply;

        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(buf);
        data.write(input);

        status_t result = remote()->transact(QUEUE_BUFFER, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }

        result = reply.read(*output);
        if (result != NO_ERROR) {
            return result;
        }

        result = reply.readInt32();
        return result;
    }

    virtual status_t queueBuffers(const std::vector<QueueBufferInput>& inputs,
                                  std::vector<QueueBufferOutput>* outputs) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeVectorSize(inputs);
        for (const QueueBufferInput& input : inputs) {
            data.write(input);
        }
        status_t result = remote()->transact(QUEUE_BUFFERS, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.resizeOutVector(outputs);
        for (QueueBufferOutput& output : *outputs) {
            if (result != NO_ERROR) {
                return result;
            }
            result = reply.read(output);
        }
        return result;
    }

    virtual status_t cancelBuffer(int buf, const sp<Fence>& fence) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(buf);
        data.write(*fence.get());
        status_t result = remote()->transact(CANCEL_BUFFER, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readInt32();
        return result;
    }

    virtual status_t cancelBuffers(
            const std::vector<CancelBufferInput>& inputs,
            std::vector<status_t>* results) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeVectorSize(inputs);
        for (const CancelBufferInput& input : inputs) {
            data.write(input);
        }
        status_t result = remote()->transact(CANCEL_BUFFERS, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readInt32Vector(results);
        return result;
    }

    virtual int query(int what, int* value) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(what);
        status_t result = remote()->transact(QUERY, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        value[0] = reply.readInt32();
        result = reply.readInt32();
        return result;
    }

    virtual status_t query(const std::vector<int32_t> inputs,
                           std::vector<QueryOutput>* outputs) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32Vector(inputs);
        status_t result = remote()->transact(QUERY_MULTIPLE, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.resizeOutVector(outputs);
        for (QueryOutput& output : *outputs) {
            if (result != NO_ERROR) {
                return result;
            }
            result = reply.read(output);
        }
        return result;
    }

    virtual status_t connect(const sp<IProducerListener>& listener,
            int api, bool producerControlledByApp, QueueBufferOutput* output) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        if (listener != nullptr) {
            data.writeInt32(1);
            data.writeStrongBinder(IInterface::asBinder(listener));
        } else {
            data.writeInt32(0);
        }
        data.writeInt32(api);
        data.writeInt32(producerControlledByApp);
        status_t result = remote()->transact(CONNECT, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        reply.read(*output);
        result = reply.readInt32();
        return result;
    }

    virtual status_t disconnect(int api, DisconnectMode mode) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(api);
        data.writeInt32(static_cast<int32_t>(mode));
        status_t result =remote()->transact(DISCONNECT, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readInt32();
        return result;
    }

    virtual status_t setSidebandStream(const sp<NativeHandle>& stream) {
        Parcel data, reply;
        status_t result;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        if (stream.get()) {
            data.writeInt32(true);
            data.writeNativeHandle(stream->handle());
        } else {
            data.writeInt32(false);
        }
        if ((result = remote()->transact(SET_SIDEBAND_STREAM, data, &reply)) == NO_ERROR) {
            result = reply.readInt32();
        }
        return result;
    }

    virtual void allocateBuffers(uint32_t width, uint32_t height,
            PixelFormat format, uint64_t usage) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeUint32(width);
        data.writeUint32(height);
        data.writeInt32(static_cast<int32_t>(format));
        data.writeUint64(usage);
        status_t result = remote()->transact(ALLOCATE_BUFFERS, data, &reply, IBinder::FLAG_ONEWAY);
        if (result != NO_ERROR) {
            ALOGE("allocateBuffers failed to transact: %d", result);
        }
    }

    virtual status_t allowAllocation(bool allow) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(static_cast<int32_t>(allow));
        status_t result = remote()->transact(ALLOW_ALLOCATION, data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readInt32();
        return result;
    }

    virtual status_t setGenerationNumber(uint32_t generationNumber) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeUint32(generationNumber);
        status_t result = remote()->transact(SET_GENERATION_NUMBER, data, &reply);
        if (result == NO_ERROR) {
            result = reply.readInt32();
        }
        return result;
    }

    virtual String8 getConsumerName() const {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        status_t result = remote()->transact(GET_CONSUMER_NAME, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getConsumerName failed to transact: %d", result);
            return String8("TransactFailed");
        }
        return reply.readString8();
    }

    virtual status_t setSharedBufferMode(bool sharedBufferMode) {
        Parcel data, reply;
        data.writeInterfaceToken(
                IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(sharedBufferMode);
        status_t result = remote()->transact(SET_SHARED_BUFFER_MODE, data,
                &reply);
        if (result == NO_ERROR) {
            result = reply.readInt32();
        }
        return result;
    }

    virtual status_t setAutoRefresh(bool autoRefresh) {
        Parcel data, reply;
        data.writeInterfaceToken(
                IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(autoRefresh);
        status_t result = remote()->transact(SET_AUTO_REFRESH, data, &reply);
        if (result == NO_ERROR) {
            result = reply.readInt32();
        }
        return result;
    }

    virtual status_t setDequeueTimeout(nsecs_t timeout) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt64(timeout);
        status_t result = remote()->transact(SET_DEQUEUE_TIMEOUT, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("setDequeueTimeout failed to transact: %d", result);
            return result;
        }
        return reply.readInt32();
    }

    virtual status_t setLegacyBufferDrop(bool drop) {
        Parcel data, reply;
        data.writeInterfaceToken(
                IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeInt32(drop);
        status_t result = remote()->transact(SET_LEGACY_BUFFER_DROP,
                data, &reply);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readInt32();
        return result;
    }

    virtual status_t getLastQueuedBuffer(sp<GraphicBuffer>* outBuffer,
            sp<Fence>* outFence, float outTransformMatrix[16]) override {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        status_t result = remote()->transact(GET_LAST_QUEUED_BUFFER, data,
                &reply);
        if (result != NO_ERROR) {
            ALOGE("getLastQueuedBuffer failed to transact: %d", result);
            return result;
        }
        result = reply.readInt32();
        if (result != NO_ERROR) {
            return result;
        }
        bool hasBuffer = reply.readBool();
        sp<GraphicBuffer> buffer;
        if (hasBuffer) {
            buffer = new GraphicBuffer();
            result = reply.read(*buffer);
            if (result == NO_ERROR) {
                result = reply.read(outTransformMatrix, sizeof(float) * 16);
            }
        }
        if (result != NO_ERROR) {
            ALOGE("getLastQueuedBuffer failed to read buffer: %d", result);
            return result;
        }
        sp<Fence> fence(new Fence);
        result = reply.read(*fence);
        if (result != NO_ERROR) {
            ALOGE("getLastQueuedBuffer failed to read fence: %d", result);
            return result;
        }
        *outBuffer = buffer;
        *outFence = fence;
        return result;
    }

    virtual status_t getLastQueuedBuffer(sp<GraphicBuffer>* outBuffer, sp<Fence>* outFence,
                                         Rect* outRect, uint32_t* outTransform) override {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        status_t result = remote()->transact(GET_LAST_QUEUED_BUFFER2, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getLastQueuedBuffer failed to transact: %d", result);
            return result;
        }
        status_t remoteError = NO_ERROR;
        result = reply.readInt32(&remoteError);
        if (result != NO_ERROR) {
            ALOGE("getLastQueuedBuffer failed to read status: %d", result);
            return result;
        }
        if (remoteError != NO_ERROR) {
            return remoteError;
        }
        bool hasBuffer = false;
        result = reply.readBool(&hasBuffer);
        if (result != NO_ERROR) {
            ALOGE("getLastQueuedBuffer failed to read buffer: %d", result);
            return result;
        }
        sp<GraphicBuffer> buffer;
        if (hasBuffer) {
            buffer = new GraphicBuffer();
            result = reply.read(*buffer);
            if (result == NO_ERROR) {
                result = reply.read(*outRect);
            }
            if (result == NO_ERROR) {
                result = reply.readUint32(outTransform);
            }
        }
        if (result != NO_ERROR) {
            ALOGE("getLastQueuedBuffer failed to read buffer: %d", result);
            return result;
        }
        sp<Fence> fence(new Fence);
        result = reply.read(*fence);
        if (result != NO_ERROR) {
            ALOGE("getLastQueuedBuffer failed to read fence: %d", result);
            return result;
        }
        *outBuffer = buffer;
        *outFence = fence;
        return result;
    }

    virtual void getFrameTimestamps(FrameEventHistoryDelta* outDelta) {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(
                IGraphicBufferProducer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("IGBP::getFrameTimestamps failed to write token: %d", result);
            return;
        }
        result = remote()->transact(GET_FRAME_TIMESTAMPS, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("IGBP::getFrameTimestamps failed to transact: %d", result);
            return;
        }
        result = reply.read(*outDelta);
        if (result != NO_ERROR) {
            ALOGE("IGBP::getFrameTimestamps failed to read timestamps: %d",
                    result);
        }
    }

    virtual status_t getUniqueId(uint64_t* outId) const {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        status_t result = remote()->transact(GET_UNIQUE_ID, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getUniqueId failed to transact: %d", result);
        }
        status_t actualResult = NO_ERROR;
        result = reply.readInt32(&actualResult);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readUint64(outId);
        if (result != NO_ERROR) {
            return result;
        }
        return actualResult;
    }

    virtual status_t getConsumerUsage(uint64_t* outUsage) const {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        status_t result = remote()->transact(GET_CONSUMER_USAGE, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getConsumerUsage failed to transact: %d", result);
        }
        status_t actualResult = NO_ERROR;
        result = reply.readInt32(&actualResult);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readUint64(outUsage);
        if (result != NO_ERROR) {
            return result;
        }
        return actualResult;
    }

    virtual status_t setAutoPrerotation(bool autoPrerotation) {
        Parcel data, reply;
        data.writeInterfaceToken(IGraphicBufferProducer::getInterfaceDescriptor());
        data.writeBool(autoPrerotation);
        status_t result = remote()->transact(SET_AUTO_PREROTATION, data, &reply);
        if (result == NO_ERROR) {
            result = reply.readInt32();
        }
        return result;
    }
};

// Out-of-line virtual method definition to trigger vtable emission in this
// translation unit (see clang warning -Wweak-vtables)
BpGraphicBufferProducer::~BpGraphicBufferProducer() {}

class HpGraphicBufferProducer : public HpInterface<
        BpGraphicBufferProducer,
        H2BGraphicBufferProducerV1_0,
        H2BGraphicBufferProducerV2_0> {
public:
    explicit HpGraphicBufferProducer(const sp<IBinder>& base) : PBase(base) {}

    status_t requestBuffer(int slot, sp<GraphicBuffer>* buf) override {
        return mBase->requestBuffer(slot, buf);
    }

    status_t requestBuffers(
            const std::vector<int32_t>& slots,
            std::vector<RequestBufferOutput>* outputs) override {
        return mBase->requestBuffers(slots, outputs);
    }

    status_t setMaxDequeuedBufferCount(int maxDequeuedBuffers) override {
        return mBase->setMaxDequeuedBufferCount(maxDequeuedBuffers);
    }

    status_t setAsyncMode(bool async) override {
        return mBase->setAsyncMode(async);
    }

    status_t dequeueBuffer(int* slot, sp<Fence>* fence, uint32_t w, uint32_t h, PixelFormat format,
                           uint64_t usage, uint64_t* outBufferAge,
                           FrameEventHistoryDelta* outTimestamps) override {
        return mBase->dequeueBuffer(slot, fence, w, h, format, usage, outBufferAge, outTimestamps);
    }

    status_t dequeueBuffers(
            const std::vector<DequeueBufferInput>& inputs,
            std::vector<DequeueBufferOutput>* outputs) override {
        return mBase->dequeueBuffers(inputs, outputs);
    }

    status_t detachBuffer(int slot) override {
        return mBase->detachBuffer(slot);
    }

    status_t detachBuffers(const std::vector<int32_t>& slots,
                           std::vector<status_t>* results) override {
        return mBase->detachBuffers(slots, results);
    }

    status_t detachNextBuffer(
            sp<GraphicBuffer>* outBuffer, sp<Fence>* outFence) override {
        return mBase->detachNextBuffer(outBuffer, outFence);
    }

    status_t attachBuffer(
            int* outSlot, const sp<GraphicBuffer>& buffer) override {
        return mBase->attachBuffer(outSlot, buffer);
    }

    status_t attachBuffers(
            const std::vector<sp<GraphicBuffer>>& buffers,
            std::vector<AttachBufferOutput>* outputs) override {
        return mBase->attachBuffers(buffers, outputs);
    }

    status_t queueBuffer(
            int slot,
            const QueueBufferInput& input,
            QueueBufferOutput* output) override {
        return mBase->queueBuffer(slot, input, output);
    }

    status_t queueBuffers(const std::vector<QueueBufferInput>& inputs,
                          std::vector<QueueBufferOutput>* outputs) override {
        return mBase->queueBuffers(inputs, outputs);
    }

    status_t cancelBuffer(int slot, const sp<Fence>& fence) override {
        return mBase->cancelBuffer(slot, fence);
    }

    status_t cancelBuffers(
            const std::vector<CancelBufferInput>& inputs,
            std::vector<status_t>* results) override {
        return mBase->cancelBuffers(inputs, results);
    }

    int query(int what, int* value) override {
        return mBase->query(what, value);
    }

    status_t query(const std::vector<int32_t> inputs,
                   std::vector<QueryOutput>* outputs) override {
        return mBase->query(inputs, outputs);
    }

    status_t connect(
            const sp<IProducerListener>& listener,
            int api, bool producerControlledByApp,
            QueueBufferOutput* output) override {
        return mBase->connect(listener, api, producerControlledByApp, output);
    }

    status_t disconnect(
            int api, DisconnectMode mode = DisconnectMode::Api) override {
        return mBase->disconnect(api, mode);
    }

    status_t setSidebandStream(const sp<NativeHandle>& stream) override {
        return mBase->setSidebandStream(stream);
    }

    void allocateBuffers(uint32_t width, uint32_t height,
            PixelFormat format, uint64_t usage) override {
        return mBase->allocateBuffers(width, height, format, usage);
    }

    status_t allowAllocation(bool allow) override {
        return mBase->allowAllocation(allow);
    }

    status_t setGenerationNumber(uint32_t generationNumber) override {
        return mBase->setGenerationNumber(generationNumber);
    }

    String8 getConsumerName() const override {
        return mBase->getConsumerName();
    }

    status_t setSharedBufferMode(bool sharedBufferMode) override {
        return mBase->setSharedBufferMode(sharedBufferMode);
    }

    status_t setAutoRefresh(bool autoRefresh) override {
        return mBase->setAutoRefresh(autoRefresh);
    }

    status_t setDequeueTimeout(nsecs_t timeout) override {
        return mBase->setDequeueTimeout(timeout);
    }

    status_t setLegacyBufferDrop(bool drop) override {
        return mBase->setLegacyBufferDrop(drop);
    }

    status_t getLastQueuedBuffer(
            sp<GraphicBuffer>* outBuffer,
            sp<Fence>* outFence,
            float outTransformMatrix[16]) override {
        return mBase->getLastQueuedBuffer(
                outBuffer, outFence, outTransformMatrix);
    }

    status_t getLastQueuedBuffer(sp<GraphicBuffer>* outBuffer, sp<Fence>* outFence, Rect* outRect,
                                 uint32_t* outTransform) override {
        return mBase->getLastQueuedBuffer(outBuffer, outFence, outRect, outTransform);
    }

    void getFrameTimestamps(FrameEventHistoryDelta* outDelta) override {
        return mBase->getFrameTimestamps(outDelta);
    }

    status_t getUniqueId(uint64_t* outId) const override {
        return mBase->getUniqueId(outId);
    }

    status_t getConsumerUsage(uint64_t* outUsage) const override {
        return mBase->getConsumerUsage(outUsage);
    }

    status_t setAutoPrerotation(bool autoPrerotation) override {
        return mBase->setAutoPrerotation(autoPrerotation);
    }
};

IMPLEMENT_HYBRID_META_INTERFACE(GraphicBufferProducer,
        "android.gui.IGraphicBufferProducer");

// ----------------------------------------------------------------------

status_t IGraphicBufferProducer::setLegacyBufferDrop(bool drop) {
    // No-op for IGBP other than BufferQueue.
    (void) drop;
    return INVALID_OPERATION;
}

status_t IGraphicBufferProducer::setAutoPrerotation(bool autoPrerotation) {
    // No-op for IGBP other than BufferQueue.
    (void)autoPrerotation;
    return INVALID_OPERATION;
}

status_t IGraphicBufferProducer::exportToParcel(Parcel* parcel) {
    status_t res = OK;
    res = parcel->writeUint32(USE_BUFFER_QUEUE);
    if (res != NO_ERROR) {
        ALOGE("exportToParcel: Cannot write magic, res=%d.", res);
        return res;
    }

    return parcel->writeStrongBinder(IInterface::asBinder(this));
}

/* static */
status_t IGraphicBufferProducer::exportToParcel(const sp<IGraphicBufferProducer>& producer,
                                                Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("exportToParcel: Invalid parcel object.");
        return BAD_VALUE;
    }

    if (producer == nullptr) {
        status_t res = OK;
        res = parcel->writeUint32(IGraphicBufferProducer::USE_BUFFER_QUEUE);
        if (res != NO_ERROR) return res;
        return parcel->writeStrongBinder(nullptr);
    } else {
        return producer->exportToParcel(parcel);
    }
}

/* static */
sp<IGraphicBufferProducer> IGraphicBufferProducer::createFromParcel(const Parcel* parcel) {
    uint32_t outMagic = 0;
    status_t res = NO_ERROR;

    res = parcel->readUint32(&outMagic);
    if (res != NO_ERROR) {
        ALOGE("createFromParcel: Failed to read magic, error=%d.", res);
        return nullptr;
    }

    switch (outMagic) {
        case USE_BUFFER_QUEUE: {
            sp<IBinder> binder;
            res = parcel->readNullableStrongBinder(&binder);
            if (res != NO_ERROR) {
                ALOGE("createFromParcel: Can't read strong binder.");
                return nullptr;
            }
            return interface_cast<IGraphicBufferProducer>(binder);
        }
        case USE_BUFFER_HUB: {
            ALOGE("createFromParcel: BufferHub not implemented.");
            return nullptr;
        }
        default: {
            ALOGE("createFromParcel: Unexpected mgaic: 0x%x.", outMagic);
            return nullptr;
        }
    }
}

// ----------------------------------------------------------------------------

status_t BnGraphicBufferProducer::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    switch(code) {
        case REQUEST_BUFFER: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            int bufferIdx = data.readInt32();
            sp<GraphicBuffer> buffer;
            int result = requestBuffer(bufferIdx, &buffer);
            reply->writeInt32(buffer != nullptr);
            if (buffer != nullptr) {
                reply->write(*buffer);
            }
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case REQUEST_BUFFERS: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            std::vector<int32_t> slots;
            std::vector<RequestBufferOutput> outputs;
            status_t result = data.readInt32Vector(&slots);
            if (result != NO_ERROR) {
                return result;
            }
            (void)requestBuffers(slots, &outputs);
            result = reply->writeVectorSize(outputs);
            for (const RequestBufferOutput& output : outputs) {
                if (result != NO_ERROR) {
                    return result;
                }
                result = reply->write(output);
            }
            return result;
        }
        case SET_MAX_DEQUEUED_BUFFER_COUNT: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            int maxDequeuedBuffers = data.readInt32();
            int result = setMaxDequeuedBufferCount(maxDequeuedBuffers);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case SET_ASYNC_MODE: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            bool async = data.readInt32();
            int result = setAsyncMode(async);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case DEQUEUE_BUFFER: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            uint32_t width = data.readUint32();
            uint32_t height = data.readUint32();
            PixelFormat format = static_cast<PixelFormat>(data.readInt32());
            uint64_t usage = data.readUint64();
            uint64_t bufferAge = 0;
            bool getTimestamps = data.readBool();

            int buf = 0;
            sp<Fence> fence = Fence::NO_FENCE;
            FrameEventHistoryDelta frameTimestamps;
            int result = dequeueBuffer(&buf, &fence, width, height, format, usage, &bufferAge,
                                       getTimestamps ? &frameTimestamps : nullptr);

            if (fence == nullptr) {
                ALOGE("dequeueBuffer returned a NULL fence, setting to Fence::NO_FENCE");
                fence = Fence::NO_FENCE;
            }
            reply->writeInt32(buf);
            reply->write(*fence);
            reply->writeUint64(bufferAge);
            if (getTimestamps) {
                reply->write(frameTimestamps);
            }
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case DEQUEUE_BUFFERS: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            std::vector<DequeueBufferInput> inputs;
            std::vector<DequeueBufferOutput> outputs;
            status_t result = data.resizeOutVector(&inputs);
            if (result != NO_ERROR) {
                return result;
            }
            for (DequeueBufferInput& input : inputs) {
                result = data.read(input);
                if (result != NO_ERROR) {
                    return result;
                }
            }
            (void)dequeueBuffers(inputs, &outputs);
            result = reply->writeVectorSize(outputs);
            for (const DequeueBufferOutput& output : outputs) {
                if (result != NO_ERROR) {
                    return result;
                }
                result = reply->write(output);
            }
            return result;
        }
        case DETACH_BUFFER: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            int slot = data.readInt32();
            int result = detachBuffer(slot);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case DETACH_BUFFERS: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            std::vector<int32_t> slots;
            std::vector<status_t> results;
            status_t result = data.readInt32Vector(&slots);
            if (result != NO_ERROR) {
                return result;
            }
            (void)detachBuffers(slots, &results);
            return reply->writeInt32Vector(results);
        }
        case DETACH_NEXT_BUFFER: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            sp<GraphicBuffer> buffer;
            sp<Fence> fence;
            int32_t result = detachNextBuffer(&buffer, &fence);
            reply->writeInt32(result);
            if (result == NO_ERROR) {
                reply->writeInt32(buffer != nullptr);
                if (buffer != nullptr) {
                    reply->write(*buffer);
                }
                reply->writeInt32(fence != nullptr);
                if (fence != nullptr) {
                    reply->write(*fence);
                }
            }
            return NO_ERROR;
        }
        case ATTACH_BUFFER: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            sp<GraphicBuffer> buffer = new GraphicBuffer();
            status_t result = data.read(*buffer.get());
            int slot = 0;
            if (result == NO_ERROR) {
                result = attachBuffer(&slot, buffer);
            }
            reply->writeInt32(slot);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case ATTACH_BUFFERS: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            std::vector<sp<GraphicBuffer>> buffers;
            status_t result = data.resizeOutVector(&buffers);
            if (result != NO_ERROR) {
                return result;
            }
            for (sp<GraphicBuffer>& buffer : buffers) {
                buffer = new GraphicBuffer();
                result = data.read(*buffer.get());
                if (result != NO_ERROR) {
                    return result;
                }
            }
            std::vector<AttachBufferOutput> outputs;
            (void)attachBuffers(buffers, &outputs);
            result = reply->writeVectorSize(outputs);
            for (const AttachBufferOutput& output : outputs) {
                if (result != NO_ERROR) {
                    return result;
                }
                result = reply->write(output);
            }
            return result;
        }
        case QUEUE_BUFFER: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);

            int buf = data.readInt32();
            QueueBufferInput input(data);
            QueueBufferOutput output;
            status_t result = queueBuffer(buf, input, &output);
            reply->write(output);
            reply->writeInt32(result);

            return NO_ERROR;
        }
        case QUEUE_BUFFERS: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            std::vector<QueueBufferInput> inputs;
            status_t result = data.resizeOutVector(&inputs);
            if (result != NO_ERROR) {
                return result;
            }
            for (QueueBufferInput& input : inputs) {
                result = data.read(input);
                if (result != NO_ERROR) {
                    return result;
                }
            }
            std::vector<QueueBufferOutput> outputs;
            (void)queueBuffers(inputs, &outputs);
            result = reply->writeVectorSize(outputs);
            for (const QueueBufferOutput& output : outputs) {
                if (result != NO_ERROR) {
                    return result;
                }
                result = reply->write(output);
            }
            return result;
        }
        case CANCEL_BUFFER: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            int buf = data.readInt32();
            sp<Fence> fence = new Fence();
            status_t result = data.read(*fence.get());
            if (result == NO_ERROR) {
                result = cancelBuffer(buf, fence);
            }
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case CANCEL_BUFFERS: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            std::vector<CancelBufferInput> inputs;
            status_t result = data.resizeOutVector(&inputs);
            for (CancelBufferInput& input : inputs) {
                if (result != NO_ERROR) {
                    return result;
                }
                result = data.read(input);
            }
            if (result != NO_ERROR) {
                return result;
            }
            std::vector<status_t> results;
            result = cancelBuffers(inputs, &results);
            if (result != NO_ERROR) {
                return result;
            }
            return reply->writeInt32Vector(results);
        }
        case QUERY: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            int value = 0;
            int what = data.readInt32();
            int res = query(what, &value);
            reply->writeInt32(value);
            reply->writeInt32(res);
            return NO_ERROR;
        }
        case QUERY_MULTIPLE: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            std::vector<int32_t> inputs;
            status_t result = data.readInt32Vector(&inputs);
            if (result != NO_ERROR) {
                return result;
            }
            std::vector<QueryOutput> outputs;
            result = query(inputs, &outputs);
            if (result != NO_ERROR) {
                return result;
            }
            result = reply->writeVectorSize(outputs);
            for (const QueryOutput& output : outputs) {
                if (result != NO_ERROR) {
                    return result;
                }
                result = reply->write(output);
            }
            return result;
        }
        case CONNECT: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            sp<IProducerListener> listener;
            if (data.readInt32() == 1) {
                listener = IProducerListener::asInterface(data.readStrongBinder());
            }
            int api = data.readInt32();
            bool producerControlledByApp = data.readInt32();
            QueueBufferOutput output;
            status_t res = connect(listener, api, producerControlledByApp, &output);
            reply->write(output);
            reply->writeInt32(res);
            return NO_ERROR;
        }
        case DISCONNECT: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            int api = data.readInt32();
            DisconnectMode mode = static_cast<DisconnectMode>(data.readInt32());
            status_t res = disconnect(api, mode);
            reply->writeInt32(res);
            return NO_ERROR;
        }
        case SET_SIDEBAND_STREAM: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            sp<NativeHandle> stream;
            if (data.readInt32()) {
                stream = NativeHandle::create(data.readNativeHandle(), true);
            }
            status_t result = setSidebandStream(stream);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case ALLOCATE_BUFFERS: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            uint32_t width = data.readUint32();
            uint32_t height = data.readUint32();
            PixelFormat format = static_cast<PixelFormat>(data.readInt32());
            uint64_t usage = data.readUint64();
            allocateBuffers(width, height, format, usage);
            return NO_ERROR;
        }
        case ALLOW_ALLOCATION: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            bool allow = static_cast<bool>(data.readInt32());
            status_t result = allowAllocation(allow);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case SET_GENERATION_NUMBER: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            uint32_t generationNumber = data.readUint32();
            status_t result = setGenerationNumber(generationNumber);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case GET_CONSUMER_NAME: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            reply->writeString8(getConsumerName());
            return NO_ERROR;
        }
        case SET_SHARED_BUFFER_MODE: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            bool sharedBufferMode = data.readInt32();
            status_t result = setSharedBufferMode(sharedBufferMode);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case SET_AUTO_REFRESH: {
            CHECK_INTERFACE(IGraphicBuffer, data, reply);
            bool autoRefresh = data.readInt32();
            status_t result = setAutoRefresh(autoRefresh);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case SET_DEQUEUE_TIMEOUT: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            nsecs_t timeout = data.readInt64();
            status_t result = setDequeueTimeout(timeout);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case GET_LAST_QUEUED_BUFFER: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            sp<GraphicBuffer> buffer(nullptr);
            sp<Fence> fence(Fence::NO_FENCE);
            float transform[16] = {};
            status_t result = getLastQueuedBuffer(&buffer, &fence, transform);
            reply->writeInt32(result);
            if (result != NO_ERROR) {
                return result;
            }
            if (!buffer.get()) {
                reply->writeBool(false);
            } else {
                reply->writeBool(true);
                result = reply->write(*buffer);
                if (result == NO_ERROR) {
                    reply->write(transform, sizeof(float) * 16);
                }
            }
            if (result != NO_ERROR) {
                ALOGE("getLastQueuedBuffer failed to write buffer: %d", result);
                return result;
            }
            if (fence == nullptr) {
                ALOGE("getLastQueuedBuffer returned a NULL fence, setting to Fence::NO_FENCE");
                fence = Fence::NO_FENCE;
            }
            result = reply->write(*fence);
            if (result != NO_ERROR) {
                ALOGE("getLastQueuedBuffer failed to write fence: %d", result);
                return result;
            }
            return NO_ERROR;
        }
        case GET_LAST_QUEUED_BUFFER2: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            sp<GraphicBuffer> buffer(nullptr);
            sp<Fence> fence(Fence::NO_FENCE);
            Rect crop;
            uint32_t transform;
            status_t result = getLastQueuedBuffer(&buffer, &fence, &crop, &transform);
            reply->writeInt32(result);
            if (result != NO_ERROR) {
                return result;
            }
            if (!buffer.get()) {
                reply->writeBool(false);
            } else {
                reply->writeBool(true);
                result = reply->write(*buffer);
                if (result == NO_ERROR) {
                    result = reply->write(crop);
                }
                if (result == NO_ERROR) {
                    result = reply->writeUint32(transform);
                }
            }
            if (result != NO_ERROR) {
                ALOGE("getLastQueuedBuffer failed to write buffer: %d", result);
                return result;
            }
            if (fence == nullptr) {
                ALOGE("getLastQueuedBuffer returned a NULL fence, setting to Fence::NO_FENCE");
                fence = Fence::NO_FENCE;
            }
            result = reply->write(*fence);
            if (result != NO_ERROR) {
                ALOGE("getLastQueuedBuffer failed to write fence: %d", result);
                return result;
            }
            return NO_ERROR;
        }

        case GET_FRAME_TIMESTAMPS: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            FrameEventHistoryDelta frameTimestamps;
            getFrameTimestamps(&frameTimestamps);
            status_t result = reply->write(frameTimestamps);
            if (result != NO_ERROR) {
                ALOGE("BnGBP::GET_FRAME_TIMESTAMPS failed to write buffer: %d",
                        result);
                return result;
            }
            return NO_ERROR;
        }
        case GET_UNIQUE_ID: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            uint64_t outId = 0;
            status_t actualResult = getUniqueId(&outId);
            status_t result = reply->writeInt32(actualResult);
            if (result != NO_ERROR) {
                return result;
            }
            result = reply->writeUint64(outId);
            if (result != NO_ERROR) {
                return result;
            }
            return NO_ERROR;
        }
        case GET_CONSUMER_USAGE: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            uint64_t outUsage = 0;
            status_t actualResult = getConsumerUsage(&outUsage);
            status_t result = reply->writeInt32(actualResult);
            if (result != NO_ERROR) {
                return result;
            }
            result = reply->writeUint64(outUsage);
            if (result != NO_ERROR) {
                return result;
            }
            return NO_ERROR;
        }
        case SET_LEGACY_BUFFER_DROP: {
            CHECK_INTERFACE(IGraphicBufferProducer, data, reply);
            bool drop = data.readInt32();
            int result = setLegacyBufferDrop(drop);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case SET_AUTO_PREROTATION: {
            CHECK_INTERFACE(IGraphicBuffer, data, reply);
            bool autoPrerotation = data.readBool();
            status_t result = setAutoPrerotation(autoPrerotation);
            reply->writeInt32(result);
            return NO_ERROR;
        }
    }
    return BBinder::onTransact(code, data, reply, flags);
}

}; // namespace android
