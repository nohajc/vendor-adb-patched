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

#ifndef _LIBINPUT_INPUT_TRANSPORT_H
#define _LIBINPUT_INPUT_TRANSPORT_H

#pragma GCC system_header

/**
 * Native input transport.
 *
 * The InputChannel provides a mechanism for exchanging InputMessage structures across processes.
 *
 * The InputPublisher and InputConsumer each handle one end-point of an input channel.
 * The InputPublisher is used by the input dispatcher to send events to the application.
 * The InputConsumer is used by the application to receive events from the input dispatcher.
 */

#include <string>
#include <unordered_map>

#include <android-base/chrono_utils.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>

#include <binder/IBinder.h>
#include <binder/Parcelable.h>
#include <input/Input.h>
#include <sys/stat.h>
#include <ui/Transform.h>
#include <utils/BitSet.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>


namespace android {
class Parcel;

/*
 * Intermediate representation used to send input events and related signals.
 *
 * Note that this structure is used for IPCs so its layout must be identical
 * on 64 and 32 bit processes. This is tested in StructLayout_test.cpp.
 *
 * Since the struct must be aligned to an 8-byte boundary, there could be uninitialized bytes
 * in-between the defined fields. This padding data should be explicitly accounted for by adding
 * "empty" fields into the struct. This data is memset to zero before sending the struct across
 * the socket. Adding the explicit fields ensures that the memset is not optimized away by the
 * compiler. When a new field is added to the struct, the corresponding change
 * in StructLayout_test should be made.
 */
struct InputMessage {
    enum class Type : uint32_t {
        KEY,
        MOTION,
        FINISHED,
        FOCUS,
        CAPTURE,
        DRAG,
        TIMELINE,
        TOUCH_MODE,

        ftl_last = TOUCH_MODE
    };

    struct Header {
        Type type; // 4 bytes
        uint32_t seq;
    } header;

    // For keys and motions, rely on the fact that std::array takes up exactly as much space
    // as the underlying data. This is not guaranteed by C++, but it simplifies the conversions.
    static_assert(sizeof(std::array<uint8_t, 32>) == 32);

    // For bool values, rely on the fact that they take up exactly one byte. This is not guaranteed
    // by C++ and is implementation-dependent, but it simplifies the conversions.
    static_assert(sizeof(bool) == 1);

    // Body *must* be 8 byte aligned.
    union Body {
        struct Key {
            int32_t eventId;
            uint32_t empty1;
            nsecs_t eventTime __attribute__((aligned(8)));
            int32_t deviceId;
            int32_t source;
            int32_t displayId;
            std::array<uint8_t, 32> hmac;
            int32_t action;
            int32_t flags;
            int32_t keyCode;
            int32_t scanCode;
            int32_t metaState;
            int32_t repeatCount;
            uint32_t empty2;
            nsecs_t downTime __attribute__((aligned(8)));

            inline size_t size() const { return sizeof(Key); }
        } key;

        struct Motion {
            int32_t eventId;
            uint32_t pointerCount;
            nsecs_t eventTime __attribute__((aligned(8)));
            int32_t deviceId;
            int32_t source;
            int32_t displayId;
            std::array<uint8_t, 32> hmac;
            int32_t action;
            int32_t actionButton;
            int32_t flags;
            int32_t metaState;
            int32_t buttonState;
            MotionClassification classification; // base type: uint8_t
            uint8_t empty2[3];                   // 3 bytes to fill gap created by classification
            int32_t edgeFlags;
            nsecs_t downTime __attribute__((aligned(8)));
            float dsdx; // Begin window transform
            float dtdx; //
            float dtdy; //
            float dsdy; //
            float tx;   //
            float ty;   // End window transform
            float xPrecision;
            float yPrecision;
            float xCursorPosition;
            float yCursorPosition;
            float dsdxRaw; // Begin raw transform
            float dtdxRaw; //
            float dtdyRaw; //
            float dsdyRaw; //
            float txRaw;   //
            float tyRaw;   // End raw transform
            /**
             * The "pointers" field must be the last field of the struct InputMessage.
             * When we send the struct InputMessage across the socket, we are not
             * writing the entire "pointers" array, but only the pointerCount portion
             * of it as an optimization. Adding a field after "pointers" would break this.
             */
            struct Pointer {
                PointerProperties properties;
                PointerCoords coords;
            } pointers[MAX_POINTERS] __attribute__((aligned(8)));

            int32_t getActionId() const {
                uint32_t index = (action & AMOTION_EVENT_ACTION_POINTER_INDEX_MASK)
                        >> AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
                return pointers[index].properties.id;
            }

            inline size_t size() const {
                return sizeof(Motion) - sizeof(Pointer) * MAX_POINTERS
                        + sizeof(Pointer) * pointerCount;
            }
        } motion;

        struct Finished {
            bool handled;
            uint8_t empty[7];
            nsecs_t consumeTime; // The time when the event was consumed by the receiving end

            inline size_t size() const { return sizeof(Finished); }
        } finished;

        struct Focus {
            int32_t eventId;
            // The following 2 fields take up 4 bytes total
            bool hasFocus;
            uint8_t empty[3];

            inline size_t size() const { return sizeof(Focus); }
        } focus;

        struct Capture {
            int32_t eventId;
            bool pointerCaptureEnabled;
            uint8_t empty[3];

            inline size_t size() const { return sizeof(Capture); }
        } capture;

        struct Drag {
            int32_t eventId;
            float x;
            float y;
            bool isExiting;
            uint8_t empty[3];

            inline size_t size() const { return sizeof(Drag); }
        } drag;

        struct Timeline {
            int32_t eventId;
            uint32_t empty;
            std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline;

            inline size_t size() const { return sizeof(Timeline); }
        } timeline;

        struct TouchMode {
            int32_t eventId;
            // The following 2 fields take up 4 bytes total
            bool isInTouchMode;
            uint8_t empty[3];

            inline size_t size() const { return sizeof(TouchMode); }
        } touchMode;
    } __attribute__((aligned(8))) body;

    bool isValid(size_t actualSize) const;
    size_t size() const;
    void getSanitizedCopy(InputMessage* msg) const;
};

/*
 * An input channel consists of a local unix domain socket used to send and receive
 * input messages across processes.  Each channel has a descriptive name for debugging purposes.
 *
 * Each endpoint has its own InputChannel object that specifies its file descriptor.
 *
 * The input channel is closed when all references to it are released.
 */
class InputChannel : public Parcelable {
public:
    static std::unique_ptr<InputChannel> create(const std::string& name,
                                                android::base::unique_fd fd, sp<IBinder> token);
    InputChannel() = default;
    InputChannel(const InputChannel& other)
          : mName(other.mName), mFd(::dup(other.mFd)), mToken(other.mToken){};
    InputChannel(const std::string name, android::base::unique_fd fd, sp<IBinder> token);
    ~InputChannel() override;
    /**
     * Create a pair of input channels.
     * The two returned input channels are equivalent, and are labeled as "server" and "client"
     * for convenience. The two input channels share the same token.
     *
     * Return OK on success.
     */
    static status_t openInputChannelPair(const std::string& name,
                                         std::unique_ptr<InputChannel>& outServerChannel,
                                         std::unique_ptr<InputChannel>& outClientChannel);

    inline std::string getName() const { return mName; }
    inline const android::base::unique_fd& getFd() const { return mFd; }
    inline sp<IBinder> getToken() const { return mToken; }

    /* Send a message to the other endpoint.
     *
     * If the channel is full then the message is guaranteed not to have been sent at all.
     * Try again after the consumer has sent a finished signal indicating that it has
     * consumed some of the pending messages from the channel.
     *
     * Return OK on success.
     * Return WOULD_BLOCK if the channel is full.
     * Return DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t sendMessage(const InputMessage* msg);

    /* Receive a message sent by the other endpoint.
     *
     * If there is no message present, try again after poll() indicates that the fd
     * is readable.
     *
     * Return OK on success.
     * Return WOULD_BLOCK if there is no message present.
     * Return DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t receiveMessage(InputMessage* msg);

    /* Return a new object that has a duplicate of this channel's fd. */
    std::unique_ptr<InputChannel> dup() const;

    void copyTo(InputChannel& outChannel) const;

    status_t readFromParcel(const android::Parcel* parcel) override;
    status_t writeToParcel(android::Parcel* parcel) const override;

    /**
     * The connection token is used to identify the input connection, i.e.
     * the pair of input channels that were created simultaneously. Input channels
     * are always created in pairs, and the token can be used to find the server-side
     * input channel from the client-side input channel, and vice versa.
     *
     * Do not use connection token to check equality of a specific input channel object
     * to another, because two different (client and server) input channels will share the
     * same connection token.
     *
     * Return the token that identifies this connection.
     */
    sp<IBinder> getConnectionToken() const;

    bool operator==(const InputChannel& inputChannel) const {
        struct stat lhs, rhs;
        if (fstat(mFd.get(), &lhs) != 0) {
            return false;
        }
        if (fstat(inputChannel.getFd(), &rhs) != 0) {
            return false;
        }
        // If file descriptors are pointing to same inode they are duplicated fds.
        return inputChannel.getName() == getName() && inputChannel.getConnectionToken() == mToken &&
                lhs.st_ino == rhs.st_ino;
    }

private:
    base::unique_fd dupFd() const;

    std::string mName;
    android::base::unique_fd mFd;

    sp<IBinder> mToken;
};

/*
 * Publishes input events to an input channel.
 */
class InputPublisher {
public:
    /* Creates a publisher associated with an input channel. */
    explicit InputPublisher(const std::shared_ptr<InputChannel>& channel);

    /* Destroys the publisher and releases its input channel. */
    ~InputPublisher();

    /* Gets the underlying input channel. */
    inline std::shared_ptr<InputChannel> getChannel() { return mChannel; }

    /* Publishes a key event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Returns BAD_VALUE if seq is 0.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishKeyEvent(uint32_t seq, int32_t eventId, int32_t deviceId, int32_t source,
                             int32_t displayId, std::array<uint8_t, 32> hmac, int32_t action,
                             int32_t flags, int32_t keyCode, int32_t scanCode, int32_t metaState,
                             int32_t repeatCount, nsecs_t downTime, nsecs_t eventTime);

    /* Publishes a motion event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Returns BAD_VALUE if seq is 0 or if pointerCount is less than 1 or greater than MAX_POINTERS.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishMotionEvent(uint32_t seq, int32_t eventId, int32_t deviceId, int32_t source,
                                int32_t displayId, std::array<uint8_t, 32> hmac, int32_t action,
                                int32_t actionButton, int32_t flags, int32_t edgeFlags,
                                int32_t metaState, int32_t buttonState,
                                MotionClassification classification, const ui::Transform& transform,
                                float xPrecision, float yPrecision, float xCursorPosition,
                                float yCursorPosition, const ui::Transform& rawTransform,
                                nsecs_t downTime, nsecs_t eventTime, uint32_t pointerCount,
                                const PointerProperties* pointerProperties,
                                const PointerCoords* pointerCoords);

    /* Publishes a focus event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishFocusEvent(uint32_t seq, int32_t eventId, bool hasFocus);

    /* Publishes a capture event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishCaptureEvent(uint32_t seq, int32_t eventId, bool pointerCaptureEnabled);

    /* Publishes a drag event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishDragEvent(uint32_t seq, int32_t eventId, float x, float y, bool isExiting);

    /* Publishes a touch mode event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishTouchModeEvent(uint32_t seq, int32_t eventId, bool isInTouchMode);

    struct Finished {
        uint32_t seq;
        bool handled;
        nsecs_t consumeTime;
    };

    struct Timeline {
        int32_t inputEventId;
        std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline;
    };

    typedef std::variant<Finished, Timeline> ConsumerResponse;
    /* Receive a signal from the consumer in reply to the original dispatch signal.
     * If a signal was received, returns a Finished or a Timeline object.
     * The InputConsumer should return a Finished object for every InputMessage that it is sent
     * to confirm that it has been processed and that the InputConsumer is responsive.
     * If several InputMessages are sent to InputConsumer, it's possible to receive Finished
     * events out of order for those messages.
     *
     * The Timeline object is returned whenever the receiving end has processed a graphical frame
     * and is returning the timeline of the frame. Not all input events will cause a Timeline
     * object to be returned, and there is not guarantee about when it will arrive.
     *
     * If an object of Finished is returned, the returned sequence number is never 0 unless the
     * operation failed.
     *
     * Returned error codes:
     *         OK on success.
     *         WOULD_BLOCK if there is no signal present.
     *         DEAD_OBJECT if the channel's peer has been closed.
     *         Other errors probably indicate that the channel is broken.
     */
    android::base::Result<ConsumerResponse> receiveConsumerResponse();

private:
    std::shared_ptr<InputChannel> mChannel;
};

/*
 * Consumes input events from an input channel.
 */
class InputConsumer {
public:
    /* Creates a consumer associated with an input channel. */
    explicit InputConsumer(const std::shared_ptr<InputChannel>& channel);

    /* Destroys the consumer and releases its input channel. */
    ~InputConsumer();

    /* Gets the underlying input channel. */
    inline std::shared_ptr<InputChannel> getChannel() { return mChannel; }

    /* Consumes an input event from the input channel and copies its contents into
     * an InputEvent object created using the specified factory.
     *
     * Tries to combine a series of move events into larger batches whenever possible.
     *
     * If consumeBatches is false, then defers consuming pending batched events if it
     * is possible for additional samples to be added to them later.  Call hasPendingBatch()
     * to determine whether a pending batch is available to be consumed.
     *
     * If consumeBatches is true, then events are still batched but they are consumed
     * immediately as soon as the input channel is exhausted.
     *
     * The frameTime parameter specifies the time when the current display frame started
     * rendering in the CLOCK_MONOTONIC time base, or -1 if unknown.
     *
     * The returned sequence number is never 0 unless the operation failed.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if there is no event present.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Returns NO_MEMORY if the event could not be created.
     * Other errors probably indicate that the channel is broken.
     */
    status_t consume(InputEventFactoryInterface* factory, bool consumeBatches, nsecs_t frameTime,
                     uint32_t* outSeq, InputEvent** outEvent);

    /* Sends a finished signal to the publisher to inform it that the message
     * with the specified sequence number has finished being process and whether
     * the message was handled by the consumer.
     *
     * Returns OK on success.
     * Returns BAD_VALUE if seq is 0.
     * Other errors probably indicate that the channel is broken.
     */
    status_t sendFinishedSignal(uint32_t seq, bool handled);

    status_t sendTimeline(int32_t inputEventId,
                          std::array<nsecs_t, GraphicsTimeline::SIZE> timeline);

    /* Returns true if there is a pending batch.
     *
     * Should be called after calling consume() with consumeBatches == false to determine
     * whether consume() should be called again later on with consumeBatches == true.
     */
    bool hasPendingBatch() const;

    /* Returns the source of first pending batch if exist.
     *
     * Should be called after calling consume() with consumeBatches == false to determine
     * whether consume() should be called again later on with consumeBatches == true.
     */
    int32_t getPendingBatchSource() const;

    std::string dump() const;

private:
    // True if touch resampling is enabled.
    const bool mResampleTouch;

    std::shared_ptr<InputChannel> mChannel;

    // The current input message.
    InputMessage mMsg;

    // True if mMsg contains a valid input message that was deferred from the previous
    // call to consume and that still needs to be handled.
    bool mMsgDeferred;

    // Batched motion events per device and source.
    struct Batch {
        std::vector<InputMessage> samples;
    };
    std::vector<Batch> mBatches;

    // Touch state per device and source, only for sources of class pointer.
    struct History {
        nsecs_t eventTime;
        BitSet32 idBits;
        int32_t idToIndex[MAX_POINTER_ID + 1];
        PointerCoords pointers[MAX_POINTERS];

        void initializeFrom(const InputMessage& msg) {
            eventTime = msg.body.motion.eventTime;
            idBits.clear();
            for (uint32_t i = 0; i < msg.body.motion.pointerCount; i++) {
                uint32_t id = msg.body.motion.pointers[i].properties.id;
                idBits.markBit(id);
                idToIndex[id] = i;
                pointers[i].copyFrom(msg.body.motion.pointers[i].coords);
            }
        }

        void initializeFrom(const History& other) {
            eventTime = other.eventTime;
            idBits = other.idBits; // temporary copy
            for (size_t i = 0; i < other.idBits.count(); i++) {
                uint32_t id = idBits.clearFirstMarkedBit();
                int32_t index = other.idToIndex[id];
                idToIndex[id] = index;
                pointers[index].copyFrom(other.pointers[index]);
            }
            idBits = other.idBits; // final copy
        }

        const PointerCoords& getPointerById(uint32_t id) const {
            return pointers[idToIndex[id]];
        }

        bool hasPointerId(uint32_t id) const {
            return idBits.hasBit(id);
        }
    };
    struct TouchState {
        int32_t deviceId;
        int32_t source;
        size_t historyCurrent;
        size_t historySize;
        History history[2];
        History lastResample;

        void initialize(int32_t deviceId, int32_t source) {
            this->deviceId = deviceId;
            this->source = source;
            historyCurrent = 0;
            historySize = 0;
            lastResample.eventTime = 0;
            lastResample.idBits.clear();
        }

        void addHistory(const InputMessage& msg) {
            historyCurrent ^= 1;
            if (historySize < 2) {
                historySize += 1;
            }
            history[historyCurrent].initializeFrom(msg);
        }

        const History* getHistory(size_t index) const {
            return &history[(historyCurrent + index) & 1];
        }

        bool recentCoordinatesAreIdentical(uint32_t id) const {
            // Return true if the two most recently received "raw" coordinates are identical
            if (historySize < 2) {
                return false;
            }
            if (!getHistory(0)->hasPointerId(id) || !getHistory(1)->hasPointerId(id)) {
                return false;
            }
            float currentX = getHistory(0)->getPointerById(id).getX();
            float currentY = getHistory(0)->getPointerById(id).getY();
            float previousX = getHistory(1)->getPointerById(id).getX();
            float previousY = getHistory(1)->getPointerById(id).getY();
            if (currentX == previousX && currentY == previousY) {
                return true;
            }
            return false;
        }
    };
    std::vector<TouchState> mTouchStates;

    // Chain of batched sequence numbers.  When multiple input messages are combined into
    // a batch, we append a record here that associates the last sequence number in the
    // batch with the previous one.  When the finished signal is sent, we traverse the
    // chain to individually finish all input messages that were part of the batch.
    struct SeqChain {
        uint32_t seq;   // sequence number of batched input message
        uint32_t chain; // sequence number of previous batched input message
    };
    std::vector<SeqChain> mSeqChains;

    // The time at which each event with the sequence number 'seq' was consumed.
    // This data is provided in 'finishInputEvent' so that the receiving end can measure the latency
    // This collection is populated when the event is received, and the entries are erased when the
    // events are finished. It should not grow infinitely because if an event is not ack'd, ANR
    // will be raised for that connection, and no further events will be posted to that channel.
    std::unordered_map<uint32_t /*seq*/, nsecs_t /*consumeTime*/> mConsumeTimes;

    status_t consumeBatch(InputEventFactoryInterface* factory,
            nsecs_t frameTime, uint32_t* outSeq, InputEvent** outEvent);
    status_t consumeSamples(InputEventFactoryInterface* factory,
            Batch& batch, size_t count, uint32_t* outSeq, InputEvent** outEvent);

    void updateTouchState(InputMessage& msg);
    void resampleTouchState(nsecs_t frameTime, MotionEvent* event,
            const InputMessage *next);

    ssize_t findBatch(int32_t deviceId, int32_t source) const;
    ssize_t findTouchState(int32_t deviceId, int32_t source) const;

    nsecs_t getConsumeTime(uint32_t seq) const;
    void popConsumeTime(uint32_t seq);
    status_t sendUnchainedFinishedSignal(uint32_t seq, bool handled);

    static void rewriteMessage(TouchState& state, InputMessage& msg);
    static void initializeKeyEvent(KeyEvent* event, const InputMessage* msg);
    static void initializeMotionEvent(MotionEvent* event, const InputMessage* msg);
    static void initializeFocusEvent(FocusEvent* event, const InputMessage* msg);
    static void initializeCaptureEvent(CaptureEvent* event, const InputMessage* msg);
    static void initializeDragEvent(DragEvent* event, const InputMessage* msg);
    static void initializeTouchModeEvent(TouchModeEvent* event, const InputMessage* msg);
    static void addSample(MotionEvent* event, const InputMessage* msg);
    static bool canAddSample(const Batch& batch, const InputMessage* msg);
    static ssize_t findSampleNoLaterThan(const Batch& batch, nsecs_t time);
    static bool shouldResampleTool(int32_t toolType);

    static bool isTouchResamplingEnabled();
};

} // namespace android

#endif // _LIBINPUT_INPUT_TRANSPORT_H
