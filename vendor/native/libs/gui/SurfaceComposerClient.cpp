/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define LOG_TAG "SurfaceComposerClient"

#include <stdint.h>
#include <sys/types.h>

#include <android/gui/IWindowInfosListener.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/SortedVector.h>
#include <utils/String8.h>
#include <utils/threads.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>

#include <system/graphics.h>

#include <gui/BufferItemConsumer.h>
#include <gui/CpuConsumer.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/ISurfaceComposer.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerState.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/WindowInfo.h>
#include <private/gui/ParcelUtils.h>
#include <ui/DisplayMode.h>
#include <ui/DynamicDisplayInfo.h>

#include <private/gui/ComposerService.h>

// This server size should always be smaller than the server cache size
#define BUFFER_CACHE_MAX_SIZE 64

namespace android {

using gui::FocusRequest;
using gui::WindowInfo;
using gui::WindowInfoHandle;
using gui::WindowInfosListener;
using ui::ColorMode;
// ---------------------------------------------------------------------------

ANDROID_SINGLETON_STATIC_INSTANCE(ComposerService);

ComposerService::ComposerService()
: Singleton<ComposerService>() {
    Mutex::Autolock _l(mLock);
    connectLocked();
}

bool ComposerService::connectLocked() {
    const String16 name("SurfaceFlinger");
    mComposerService = waitForService<ISurfaceComposer>(name);
    if (mComposerService == nullptr) {
        return false; // fatal error or permission problem
    }

    // Create the death listener.
    class DeathObserver : public IBinder::DeathRecipient {
        ComposerService& mComposerService;
        virtual void binderDied(const wp<IBinder>& who) {
            ALOGW("ComposerService remote (surfaceflinger) died [%p]",
                  who.unsafe_get());
            mComposerService.composerServiceDied();
        }
     public:
        explicit DeathObserver(ComposerService& mgr) : mComposerService(mgr) { }
    };

    mDeathObserver = new DeathObserver(*const_cast<ComposerService*>(this));
    IInterface::asBinder(mComposerService)->linkToDeath(mDeathObserver);
    return true;
}

/*static*/ sp<ISurfaceComposer> ComposerService::getComposerService() {
    ComposerService& instance = ComposerService::getInstance();
    Mutex::Autolock _l(instance.mLock);
    if (instance.mComposerService == nullptr) {
        if (ComposerService::getInstance().connectLocked()) {
            ALOGD("ComposerService reconnected");
            WindowInfosListenerReporter::getInstance()->reconnect(instance.mComposerService);
        }
    }
    return instance.mComposerService;
}

void ComposerService::composerServiceDied()
{
    Mutex::Autolock _l(mLock);
    mComposerService = nullptr;
    mDeathObserver = nullptr;
}

class DefaultComposerClient: public Singleton<DefaultComposerClient> {
    Mutex mLock;
    sp<SurfaceComposerClient> mClient;
    friend class Singleton<ComposerService>;
public:
    static sp<SurfaceComposerClient> getComposerClient() {
        DefaultComposerClient& dc = DefaultComposerClient::getInstance();
        Mutex::Autolock _l(dc.mLock);
        if (dc.mClient == nullptr) {
            dc.mClient = new SurfaceComposerClient;
        }
        return dc.mClient;
    }
};
ANDROID_SINGLETON_STATIC_INSTANCE(DefaultComposerClient);


sp<SurfaceComposerClient> SurfaceComposerClient::getDefault() {
    return DefaultComposerClient::getComposerClient();
}

JankDataListener::~JankDataListener() {
}

// ---------------------------------------------------------------------------

// TransactionCompletedListener does not use ANDROID_SINGLETON_STATIC_INSTANCE because it needs
// to be able to return a sp<> to its instance to pass to SurfaceFlinger.
// ANDROID_SINGLETON_STATIC_INSTANCE only allows a reference to an instance.

// 0 is an invalid callback id
TransactionCompletedListener::TransactionCompletedListener() : mCallbackIdCounter(1) {}

int64_t TransactionCompletedListener::getNextIdLocked() {
    return mCallbackIdCounter++;
}

sp<TransactionCompletedListener> TransactionCompletedListener::sInstance = nullptr;

void TransactionCompletedListener::setInstance(const sp<TransactionCompletedListener>& listener) {
    sInstance = listener;
}

sp<TransactionCompletedListener> TransactionCompletedListener::getInstance() {
    if (sInstance == nullptr) {
        sInstance = new TransactionCompletedListener;
    }
    return sInstance;
}

sp<ITransactionCompletedListener> TransactionCompletedListener::getIInstance() {
    return static_cast<sp<ITransactionCompletedListener>>(getInstance());
}

void TransactionCompletedListener::startListeningLocked() {
    if (mListening) {
        return;
    }
    ProcessState::self()->startThreadPool();
    mListening = true;
}

CallbackId TransactionCompletedListener::addCallbackFunction(
        const TransactionCompletedCallback& callbackFunction,
        const std::unordered_set<sp<SurfaceControl>, SurfaceComposerClient::SCHash>&
                surfaceControls,
        CallbackId::Type callbackType) {
    std::lock_guard<std::mutex> lock(mMutex);
    startListeningLocked();

    CallbackId callbackId(getNextIdLocked(), callbackType);
    mCallbacks[callbackId].callbackFunction = callbackFunction;
    auto& callbackSurfaceControls = mCallbacks[callbackId].surfaceControls;

    for (const auto& surfaceControl : surfaceControls) {
        callbackSurfaceControls[surfaceControl->getHandle()] = surfaceControl;
    }

    return callbackId;
}

void TransactionCompletedListener::addJankListener(const sp<JankDataListener>& listener,
                                                   sp<SurfaceControl> surfaceControl) {
    std::lock_guard<std::mutex> lock(mMutex);
    mJankListeners.insert({surfaceControl->getLayerId(), listener});
}

void TransactionCompletedListener::removeJankListener(const sp<JankDataListener>& listener) {
    std::lock_guard<std::mutex> lock(mMutex);
    for (auto it = mJankListeners.begin(); it != mJankListeners.end();) {
        if (it->second == listener) {
            it = mJankListeners.erase(it);
        } else {
            it++;
        }
    }
}

void TransactionCompletedListener::setReleaseBufferCallback(const ReleaseCallbackId& callbackId,
                                                            ReleaseBufferCallback listener) {
    std::scoped_lock<std::mutex> lock(mMutex);
    mReleaseBufferCallbacks[callbackId] = listener;
}

void TransactionCompletedListener::removeReleaseBufferCallback(
        const ReleaseCallbackId& callbackId) {
    std::scoped_lock<std::mutex> lock(mMutex);
    mReleaseBufferCallbacks.erase(callbackId);
}

void TransactionCompletedListener::addSurfaceStatsListener(void* context, void* cookie,
        sp<SurfaceControl> surfaceControl, SurfaceStatsCallback listener) {
    std::scoped_lock<std::recursive_mutex> lock(mSurfaceStatsListenerMutex);
    mSurfaceStatsListeners.insert(
            {surfaceControl->getLayerId(), SurfaceStatsCallbackEntry(context, cookie, listener)});
}

void TransactionCompletedListener::removeSurfaceStatsListener(void* context, void* cookie) {
    std::scoped_lock<std::recursive_mutex> lock(mSurfaceStatsListenerMutex);
    for (auto it = mSurfaceStatsListeners.begin(); it != mSurfaceStatsListeners.end();) {
        auto [itContext, itCookie, itListener] = it->second;
        if (itContext == context && itCookie == cookie) {
            it = mSurfaceStatsListeners.erase(it);
        } else {
            it++;
        }
    }
}

void TransactionCompletedListener::addSurfaceControlToCallbacks(
        const sp<SurfaceControl>& surfaceControl,
        const std::unordered_set<CallbackId, CallbackIdHash>& callbackIds) {
    std::lock_guard<std::mutex> lock(mMutex);

    for (auto callbackId : callbackIds) {
        mCallbacks[callbackId].surfaceControls.emplace(std::piecewise_construct,
                                                       std::forward_as_tuple(
                                                               surfaceControl->getHandle()),
                                                       std::forward_as_tuple(surfaceControl));
    }
}

void TransactionCompletedListener::onTransactionCompleted(ListenerStats listenerStats) {
    std::unordered_map<CallbackId, CallbackTranslation, CallbackIdHash> callbacksMap;
    std::multimap<int32_t, sp<JankDataListener>> jankListenersMap;
    {
        std::lock_guard<std::mutex> lock(mMutex);

        /* This listener knows all the sp<IBinder> to sp<SurfaceControl> for all its registered
         * callbackIds, except for when Transactions are merged together. This probably cannot be
         * solved before this point because the Transactions could be merged together and applied in
         * a different process.
         *
         * Fortunately, we get all the callbacks for this listener for the same frame together at
         * the same time. This means if any Transactions were merged together, we will get their
         * callbacks at the same time. We can combine all the sp<IBinder> to sp<SurfaceControl> maps
         * for all the callbackIds to generate one super map that contains all the sp<IBinder> to
         * sp<SurfaceControl> that could possibly exist for the callbacks.
         */
        callbacksMap = mCallbacks;
        jankListenersMap = mJankListeners;
        for (const auto& transactionStats : listenerStats.transactionStats) {
            for (auto& callbackId : transactionStats.callbackIds) {
                mCallbacks.erase(callbackId);
            }
        }
    }
    for (const auto& transactionStats : listenerStats.transactionStats) {
        // handle on commit callbacks
        for (auto callbackId : transactionStats.callbackIds) {
            if (callbackId.type != CallbackId::Type::ON_COMMIT) {
                continue;
            }
            auto& [callbackFunction, callbackSurfaceControls] = callbacksMap[callbackId];
            if (!callbackFunction) {
                ALOGE("cannot call null callback function, skipping");
                continue;
            }
            std::vector<SurfaceControlStats> surfaceControlStats;
            for (const auto& surfaceStats : transactionStats.surfaceStats) {
                surfaceControlStats
                        .emplace_back(callbacksMap[callbackId]
                                              .surfaceControls[surfaceStats.surfaceControl],
                                      transactionStats.latchTime, surfaceStats.acquireTime,
                                      transactionStats.presentFence,
                                      surfaceStats.previousReleaseFence, surfaceStats.transformHint,
                                      surfaceStats.eventStats, surfaceStats.currentMaxAcquiredBufferCount);
            }

            callbackFunction(transactionStats.latchTime, transactionStats.presentFence,
                             surfaceControlStats);
        }

        // handle on complete callbacks
        for (auto callbackId : transactionStats.callbackIds) {
            if (callbackId.type != CallbackId::Type::ON_COMPLETE) {
                continue;
            }
            auto& [callbackFunction, callbackSurfaceControls] = callbacksMap[callbackId];
            if (!callbackFunction) {
                ALOGE("cannot call null callback function, skipping");
                continue;
            }
            std::vector<SurfaceControlStats> surfaceControlStats;
            for (const auto& surfaceStats : transactionStats.surfaceStats) {
                surfaceControlStats
                        .emplace_back(callbacksMap[callbackId]
                                              .surfaceControls[surfaceStats.surfaceControl],
                                      transactionStats.latchTime, surfaceStats.acquireTime,
                                      transactionStats.presentFence,
                                      surfaceStats.previousReleaseFence, surfaceStats.transformHint,
                                      surfaceStats.eventStats, surfaceStats.currentMaxAcquiredBufferCount);
                if (callbacksMap[callbackId].surfaceControls[surfaceStats.surfaceControl]) {
                    callbacksMap[callbackId]
                            .surfaceControls[surfaceStats.surfaceControl]
                            ->setTransformHint(surfaceStats.transformHint);
                }
                // If there is buffer id set, we look up any pending client release buffer callbacks
                // and call them. This is a performance optimization when we have a transaction
                // callback and a release buffer callback happening at the same time to avoid an
                // additional ipc call from the server.
                if (surfaceStats.previousReleaseCallbackId != ReleaseCallbackId::INVALID_ID) {
                    ReleaseBufferCallback callback;
                    {
                        std::scoped_lock<std::mutex> lock(mMutex);
                        callback = popReleaseBufferCallbackLocked(
                                surfaceStats.previousReleaseCallbackId);
                    }
                    if (callback) {
                        callback(surfaceStats.previousReleaseCallbackId,
                                 surfaceStats.previousReleaseFence
                                         ? surfaceStats.previousReleaseFence
                                         : Fence::NO_FENCE,
                                 surfaceStats.transformHint,
                                 surfaceStats.currentMaxAcquiredBufferCount);
                    }
                }
            }

            callbackFunction(transactionStats.latchTime, transactionStats.presentFence,
                             surfaceControlStats);
        }

        for (const auto& surfaceStats : transactionStats.surfaceStats) {
            // The callbackMap contains the SurfaceControl object, which we need to look up the
            // layerId. Since we don't know which callback contains the SurfaceControl, iterate
            // through all until the SC is found.
            int32_t layerId = -1;
            for (auto callbackId : transactionStats.callbackIds) {
                sp<SurfaceControl> sc =
                        callbacksMap[callbackId].surfaceControls[surfaceStats.surfaceControl];
                if (sc != nullptr) {
                    layerId = sc->getLayerId();
                    break;
                }
            }

            {
                // Acquire surface stats listener lock such that we guarantee that after calling
                // unregister, there won't be any further callback.
                std::scoped_lock<std::recursive_mutex> lock(mSurfaceStatsListenerMutex);
                auto listenerRange = mSurfaceStatsListeners.equal_range(layerId);
                for (auto it = listenerRange.first; it != listenerRange.second; it++) {
                    auto entry = it->second;
                    entry.callback(entry.context, transactionStats.latchTime,
                        transactionStats.presentFence, surfaceStats);
                }
            }

            if (surfaceStats.jankData.empty()) continue;
            auto jankRange = jankListenersMap.equal_range(layerId);
            for (auto it = jankRange.first; it != jankRange.second; it++) {
                it->second->onJankDataAvailable(surfaceStats.jankData);
            }
        }
    }
}

void TransactionCompletedListener::onReleaseBuffer(ReleaseCallbackId callbackId,
                                                   sp<Fence> releaseFence, uint32_t transformHint,
                                                   uint32_t currentMaxAcquiredBufferCount) {
    ReleaseBufferCallback callback;
    {
        std::scoped_lock<std::mutex> lock(mMutex);
        callback = popReleaseBufferCallbackLocked(callbackId);
    }
    if (!callback) {
        ALOGE("Could not call release buffer callback, buffer not found %s",
              callbackId.to_string().c_str());
        return;
    }
    callback(callbackId, releaseFence, transformHint, currentMaxAcquiredBufferCount);
}

ReleaseBufferCallback TransactionCompletedListener::popReleaseBufferCallbackLocked(
        const ReleaseCallbackId& callbackId) {
    ReleaseBufferCallback callback;
    auto itr = mReleaseBufferCallbacks.find(callbackId);
    if (itr == mReleaseBufferCallbacks.end()) {
        return nullptr;
    }
    callback = itr->second;
    mReleaseBufferCallbacks.erase(itr);
    return callback;
}

// ---------------------------------------------------------------------------

void removeDeadBufferCallback(void* /*context*/, uint64_t graphicBufferId);

/**
 * We use the BufferCache to reduce the overhead of exchanging GraphicBuffers with
 * the server. If we were to simply parcel the GraphicBuffer we would pay two overheads
 *     1. Cost of sending the FD
 *     2. Cost of importing the GraphicBuffer with the mapper in the receiving process.
 * To ease this cost we implement the following scheme of caching buffers to integers,
 * or said-otherwise, naming them with integers. This is the scheme known as slots in
 * the legacy BufferQueue system.
 *     1. When sending Buffers to SurfaceFlinger we look up the Buffer in the cache.
 *     2. If there is a cache-hit we remove the Buffer from the Transaction and instead
 *        send the cached integer.
 *     3. If there is a cache miss, we cache the new buffer and send the integer
 *        along with the Buffer, SurfaceFlinger on it's side creates a new cache
 *        entry, and we use the integer for further communication.
 * A few details about lifetime:
 *     1. The cache evicts by LRU. The server side cache is keyed by BufferCache::getToken
 *        which is per process Unique. The server side cache is larger than the client side
 *        cache so that the server will never evict entries before the client.
 *     2. When the client evicts an entry it notifies the server via an uncacheBuffer
 *        transaction.
 *     3. The client only references the Buffers by ID, and uses buffer->addDeathCallback
 *        to auto-evict destroyed buffers.
 */
class BufferCache : public Singleton<BufferCache> {
public:
    BufferCache() : token(new BBinder()) {}

    sp<IBinder> getToken() {
        return IInterface::asBinder(TransactionCompletedListener::getIInstance());
    }

    status_t getCacheId(const sp<GraphicBuffer>& buffer, uint64_t* cacheId) {
        std::lock_guard<std::mutex> lock(mMutex);

        auto itr = mBuffers.find(buffer->getId());
        if (itr == mBuffers.end()) {
            return BAD_VALUE;
        }
        itr->second = getCounter();
        *cacheId = buffer->getId();
        return NO_ERROR;
    }

    uint64_t cache(const sp<GraphicBuffer>& buffer) {
        std::lock_guard<std::mutex> lock(mMutex);

        if (mBuffers.size() >= BUFFER_CACHE_MAX_SIZE) {
            evictLeastRecentlyUsedBuffer();
        }

        buffer->addDeathCallback(removeDeadBufferCallback, nullptr);

        mBuffers[buffer->getId()] = getCounter();
        return buffer->getId();
    }

    void uncache(uint64_t cacheId) {
        std::lock_guard<std::mutex> lock(mMutex);
        uncacheLocked(cacheId);
    }

    void uncacheLocked(uint64_t cacheId) REQUIRES(mMutex) {
        mBuffers.erase(cacheId);
        SurfaceComposerClient::doUncacheBufferTransaction(cacheId);
    }

private:
    void evictLeastRecentlyUsedBuffer() REQUIRES(mMutex) {
        auto itr = mBuffers.begin();
        uint64_t minCounter = itr->second;
        auto minBuffer = itr;
        itr++;

        while (itr != mBuffers.end()) {
            uint64_t counter = itr->second;
            if (counter < minCounter) {
                minCounter = counter;
                minBuffer = itr;
            }
            itr++;
        }
        uncacheLocked(minBuffer->first);
    }

    uint64_t getCounter() REQUIRES(mMutex) {
        static uint64_t counter = 0;
        return counter++;
    }

    std::mutex mMutex;
    std::map<uint64_t /*Cache id*/, uint64_t /*counter*/> mBuffers GUARDED_BY(mMutex);

    // Used by ISurfaceComposer to identify which process is sending the cached buffer.
    sp<IBinder> token;
};

ANDROID_SINGLETON_STATIC_INSTANCE(BufferCache);

void removeDeadBufferCallback(void* /*context*/, uint64_t graphicBufferId) {
    // GraphicBuffer id's are used as the cache ids.
    BufferCache::getInstance().uncache(graphicBufferId);
}

// ---------------------------------------------------------------------------

// Initialize transaction id counter used to generate transaction ids
// Transactions will start counting at 1, 0 is used for invalid transactions
std::atomic<uint32_t> SurfaceComposerClient::Transaction::idCounter = 1;

SurfaceComposerClient::Transaction::Transaction() {
    mId = generateId();
}

SurfaceComposerClient::Transaction::Transaction(const Transaction& other)
      : mId(other.mId),
        mForceSynchronous(other.mForceSynchronous),
        mTransactionNestCount(other.mTransactionNestCount),
        mAnimation(other.mAnimation),
        mEarlyWakeupStart(other.mEarlyWakeupStart),
        mEarlyWakeupEnd(other.mEarlyWakeupEnd),
        mContainsBuffer(other.mContainsBuffer),
        mDesiredPresentTime(other.mDesiredPresentTime),
        mIsAutoTimestamp(other.mIsAutoTimestamp),
        mFrameTimelineInfo(other.mFrameTimelineInfo),
        mApplyToken(other.mApplyToken) {
    mDisplayStates = other.mDisplayStates;
    mComposerStates = other.mComposerStates;
    mInputWindowCommands = other.mInputWindowCommands;
    mListenerCallbacks = other.mListenerCallbacks;
}

void SurfaceComposerClient::Transaction::sanitize() {
    for (auto & [handle, composerState] : mComposerStates) {
        composerState.state.sanitize(0 /* permissionMask */);
    }
    mInputWindowCommands.clear();
}

std::unique_ptr<SurfaceComposerClient::Transaction>
SurfaceComposerClient::Transaction::createFromParcel(const Parcel* parcel) {
    auto transaction = std::make_unique<Transaction>();
    if (transaction->readFromParcel(parcel) == NO_ERROR) {
        return transaction;
    }
    return nullptr;
}

int64_t SurfaceComposerClient::Transaction::generateId() {
    return (((int64_t)getpid()) << 32) | idCounter++;
}

status_t SurfaceComposerClient::Transaction::readFromParcel(const Parcel* parcel) {
    const uint32_t forceSynchronous = parcel->readUint32();
    const uint32_t transactionNestCount = parcel->readUint32();
    const bool animation = parcel->readBool();
    const bool earlyWakeupStart = parcel->readBool();
    const bool earlyWakeupEnd = parcel->readBool();
    const bool containsBuffer = parcel->readBool();
    const int64_t desiredPresentTime = parcel->readInt64();
    const bool isAutoTimestamp = parcel->readBool();
    FrameTimelineInfo frameTimelineInfo;
    SAFE_PARCEL(frameTimelineInfo.read, *parcel);

    sp<IBinder> applyToken;
    parcel->readNullableStrongBinder(&applyToken);
    size_t count = static_cast<size_t>(parcel->readUint32());
    if (count > parcel->dataSize()) {
        return BAD_VALUE;
    }
    SortedVector<DisplayState> displayStates;
    displayStates.setCapacity(count);
    for (size_t i = 0; i < count; i++) {
        DisplayState displayState;
        if (displayState.read(*parcel) == BAD_VALUE) {
            return BAD_VALUE;
        }
        displayStates.add(displayState);
    }

    count = static_cast<size_t>(parcel->readUint32());
    if (count > parcel->dataSize()) {
        return BAD_VALUE;
    }
    std::unordered_map<sp<ITransactionCompletedListener>, CallbackInfo, TCLHash> listenerCallbacks;
    listenerCallbacks.reserve(count);
    for (size_t i = 0; i < count; i++) {
        sp<ITransactionCompletedListener> listener =
                interface_cast<ITransactionCompletedListener>(parcel->readStrongBinder());
        size_t numCallbackIds = parcel->readUint32();
        if (numCallbackIds > parcel->dataSize()) {
            return BAD_VALUE;
        }
        for (size_t j = 0; j < numCallbackIds; j++) {
            CallbackId id;
            parcel->readParcelable(&id);
            listenerCallbacks[listener].callbackIds.insert(id);
        }
        size_t numSurfaces = parcel->readUint32();
        if (numSurfaces > parcel->dataSize()) {
            return BAD_VALUE;
        }
        for (size_t j = 0; j < numSurfaces; j++) {
            sp<SurfaceControl> surface;
            SAFE_PARCEL(SurfaceControl::readFromParcel, *parcel, &surface);
            listenerCallbacks[listener].surfaceControls.insert(surface);
        }
    }

    count = static_cast<size_t>(parcel->readUint32());
    if (count > parcel->dataSize()) {
        return BAD_VALUE;
    }
    std::unordered_map<sp<IBinder>, ComposerState, IBinderHash> composerStates;
    composerStates.reserve(count);
    for (size_t i = 0; i < count; i++) {
        sp<IBinder> surfaceControlHandle;
        SAFE_PARCEL(parcel->readStrongBinder, &surfaceControlHandle);

        ComposerState composerState;
        if (composerState.read(*parcel) == BAD_VALUE) {
            return BAD_VALUE;
        }
        composerStates[surfaceControlHandle] = composerState;
    }

    InputWindowCommands inputWindowCommands;
    inputWindowCommands.read(*parcel);

    // Parsing was successful. Update the object.
    mForceSynchronous = forceSynchronous;
    mTransactionNestCount = transactionNestCount;
    mAnimation = animation;
    mEarlyWakeupStart = earlyWakeupStart;
    mEarlyWakeupEnd = earlyWakeupEnd;
    mContainsBuffer = containsBuffer;
    mDesiredPresentTime = desiredPresentTime;
    mIsAutoTimestamp = isAutoTimestamp;
    mFrameTimelineInfo = frameTimelineInfo;
    mDisplayStates = displayStates;
    mListenerCallbacks = listenerCallbacks;
    mComposerStates = composerStates;
    mInputWindowCommands = inputWindowCommands;
    mApplyToken = applyToken;
    return NO_ERROR;
}

status_t SurfaceComposerClient::Transaction::writeToParcel(Parcel* parcel) const {
    // If we write the Transaction to a parcel, we want to ensure the Buffers are cached
    // before crossing the IPC boundary. Otherwise the receiving party will cache the buffers
    // but is unlikely to use them again as they are owned by the other process.
    // You may be asking yourself, is this const cast safe? Const cast is safe up
    // until the point where you try and write to an object that was originally const at which
    // point we enter undefined behavior. In this case we are safe though, because there are
    // two possibilities:
    //    1. The SurfaceComposerClient::Transaction was originally non-const. Safe.
    //    2. It was originall const! In this case not only was it useless, but it by definition
    //       contains no composer states and so cacheBuffers will not perform any writes.

    const_cast<SurfaceComposerClient::Transaction*>(this)->cacheBuffers();

    parcel->writeUint32(mForceSynchronous);
    parcel->writeUint32(mTransactionNestCount);
    parcel->writeBool(mAnimation);
    parcel->writeBool(mEarlyWakeupStart);
    parcel->writeBool(mEarlyWakeupEnd);
    parcel->writeBool(mContainsBuffer);
    parcel->writeInt64(mDesiredPresentTime);
    parcel->writeBool(mIsAutoTimestamp);
    SAFE_PARCEL(mFrameTimelineInfo.write, *parcel);
    parcel->writeStrongBinder(mApplyToken);
    parcel->writeUint32(static_cast<uint32_t>(mDisplayStates.size()));
    for (auto const& displayState : mDisplayStates) {
        displayState.write(*parcel);
    }

    parcel->writeUint32(static_cast<uint32_t>(mListenerCallbacks.size()));
    for (auto const& [listener, callbackInfo] : mListenerCallbacks) {
        parcel->writeStrongBinder(ITransactionCompletedListener::asBinder(listener));
        parcel->writeUint32(static_cast<uint32_t>(callbackInfo.callbackIds.size()));
        for (auto callbackId : callbackInfo.callbackIds) {
            parcel->writeParcelable(callbackId);
        }
        parcel->writeUint32(static_cast<uint32_t>(callbackInfo.surfaceControls.size()));
        for (auto surfaceControl : callbackInfo.surfaceControls) {
            SAFE_PARCEL(surfaceControl->writeToParcel, *parcel);
        }
    }

    parcel->writeUint32(static_cast<uint32_t>(mComposerStates.size()));
    for (auto const& [handle, composerState] : mComposerStates) {
        SAFE_PARCEL(parcel->writeStrongBinder, handle);
        composerState.write(*parcel);
    }

    mInputWindowCommands.write(*parcel);
    return NO_ERROR;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::merge(Transaction&& other) {
    for (auto const& [handle, composerState] : other.mComposerStates) {
        if (mComposerStates.count(handle) == 0) {
            mComposerStates[handle] = composerState;
        } else {
            mComposerStates[handle].state.merge(composerState.state);
        }
    }

    for (auto const& state : other.mDisplayStates) {
        ssize_t index = mDisplayStates.indexOf(state);
        if (index < 0) {
            mDisplayStates.add(state);
        } else {
            mDisplayStates.editItemAt(static_cast<size_t>(index)).merge(state);
        }
    }

    for (const auto& [listener, callbackInfo] : other.mListenerCallbacks) {
        auto& [callbackIds, surfaceControls] = callbackInfo;
        mListenerCallbacks[listener].callbackIds.insert(std::make_move_iterator(
                                                                callbackIds.begin()),
                                                        std::make_move_iterator(callbackIds.end()));

        mListenerCallbacks[listener].surfaceControls.insert(surfaceControls.begin(),
                                                            surfaceControls.end());

        auto& currentProcessCallbackInfo =
                mListenerCallbacks[TransactionCompletedListener::getIInstance()];
        currentProcessCallbackInfo.surfaceControls
                .insert(std::make_move_iterator(surfaceControls.begin()),
                        std::make_move_iterator(surfaceControls.end()));

        // register all surface controls for all callbackIds for this listener that is merging
        for (const auto& surfaceControl : currentProcessCallbackInfo.surfaceControls) {
            TransactionCompletedListener::getInstance()
                    ->addSurfaceControlToCallbacks(surfaceControl,
                                                   currentProcessCallbackInfo.callbackIds);
        }
    }

    mInputWindowCommands.merge(other.mInputWindowCommands);

    mContainsBuffer |= other.mContainsBuffer;
    mEarlyWakeupStart = mEarlyWakeupStart || other.mEarlyWakeupStart;
    mEarlyWakeupEnd = mEarlyWakeupEnd || other.mEarlyWakeupEnd;
    mApplyToken = other.mApplyToken;

    mFrameTimelineInfo.merge(other.mFrameTimelineInfo);

    other.clear();
    return *this;
}

void SurfaceComposerClient::Transaction::clear() {
    mComposerStates.clear();
    mDisplayStates.clear();
    mListenerCallbacks.clear();
    mInputWindowCommands.clear();
    mContainsBuffer = false;
    mForceSynchronous = 0;
    mTransactionNestCount = 0;
    mAnimation = false;
    mEarlyWakeupStart = false;
    mEarlyWakeupEnd = false;
    mDesiredPresentTime = 0;
    mIsAutoTimestamp = true;
    mFrameTimelineInfo.clear();
    mApplyToken = nullptr;
}

void SurfaceComposerClient::doUncacheBufferTransaction(uint64_t cacheId) {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());

    client_cache_t uncacheBuffer;
    uncacheBuffer.token = BufferCache::getInstance().getToken();
    uncacheBuffer.id = cacheId;

    sp<IBinder> applyToken = IInterface::asBinder(TransactionCompletedListener::getIInstance());
    sf->setTransactionState(FrameTimelineInfo{}, {}, {}, 0, applyToken, {}, systemTime(), true,
                            uncacheBuffer, false, {}, 0 /* Undefined transactionId */);
}

void SurfaceComposerClient::Transaction::cacheBuffers() {
    if (!mContainsBuffer) {
        return;
    }

    size_t count = 0;
    for (auto& [handle, cs] : mComposerStates) {
        layer_state_t* s = &(mComposerStates[handle].state);
        if (!(s->what & layer_state_t::eBufferChanged)) {
            continue;
        } else if (s->what & layer_state_t::eCachedBufferChanged) {
            // If eBufferChanged and eCachedBufferChanged are both trued then that means
            // we already cached the buffer in a previous call to cacheBuffers, perhaps
            // from writeToParcel on a Transaction that was merged in to this one.
            continue;
        }

        // Don't try to cache a null buffer. Sending null buffers is cheap so we shouldn't waste
        // time trying to cache them.
        if (!s->buffer) {
            continue;
        }

        uint64_t cacheId = 0;
        status_t ret = BufferCache::getInstance().getCacheId(s->buffer, &cacheId);
        if (ret == NO_ERROR) {
            // Cache-hit. Strip the buffer and send only the id.
            s->what &= ~static_cast<uint64_t>(layer_state_t::eBufferChanged);
            s->buffer = nullptr;
        } else {
            // Cache-miss. Include the buffer and send the new cacheId.
            cacheId = BufferCache::getInstance().cache(s->buffer);
        }
        s->what |= layer_state_t::eCachedBufferChanged;
        s->cachedBuffer.token = BufferCache::getInstance().getToken();
        s->cachedBuffer.id = cacheId;

        // If we have more buffers than the size of the cache, we should stop caching so we don't
        // evict other buffers in this transaction
        count++;
        if (count >= BUFFER_CACHE_MAX_SIZE) {
            break;
        }
    }
}

status_t SurfaceComposerClient::Transaction::apply(bool synchronous) {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }

    sp<ISurfaceComposer> sf(ComposerService::getComposerService());

    bool hasListenerCallbacks = !mListenerCallbacks.empty();
    std::vector<ListenerCallbacks> listenerCallbacks;
    // For every listener with registered callbacks
    for (const auto& [listener, callbackInfo] : mListenerCallbacks) {
        auto& [callbackIds, surfaceControls] = callbackInfo;
        if (callbackIds.empty()) {
            continue;
        }

        if (surfaceControls.empty()) {
            listenerCallbacks.emplace_back(IInterface::asBinder(listener), std::move(callbackIds));
        } else {
            // If the listener has any SurfaceControls set on this Transaction update the surface
            // state
            for (const auto& surfaceControl : surfaceControls) {
                layer_state_t* s = getLayerState(surfaceControl);
                if (!s) {
                    ALOGE("failed to get layer state");
                    continue;
                }
                std::vector<CallbackId> callbacks(callbackIds.begin(), callbackIds.end());
                s->what |= layer_state_t::eHasListenerCallbacksChanged;
                s->listeners.emplace_back(IInterface::asBinder(listener), callbacks);
            }
        }
    }

    cacheBuffers();

    Vector<ComposerState> composerStates;
    Vector<DisplayState> displayStates;
    uint32_t flags = 0;

    mForceSynchronous |= synchronous;

    for (auto const& kv : mComposerStates){
        composerStates.add(kv.second);
    }

    displayStates = std::move(mDisplayStates);

    if (mForceSynchronous) {
        flags |= ISurfaceComposer::eSynchronous;
    }
    if (mAnimation) {
        flags |= ISurfaceComposer::eAnimation;
    }

    // If both mEarlyWakeupStart and mEarlyWakeupEnd are set
    // it is equivalent for none
    if (mEarlyWakeupStart && !mEarlyWakeupEnd) {
        flags |= ISurfaceComposer::eEarlyWakeupStart;
    }
    if (mEarlyWakeupEnd && !mEarlyWakeupStart) {
        flags |= ISurfaceComposer::eEarlyWakeupEnd;
    }

    sp<IBinder> applyToken = mApplyToken
            ? mApplyToken
            : IInterface::asBinder(TransactionCompletedListener::getIInstance());

    sf->setTransactionState(mFrameTimelineInfo, composerStates, displayStates, flags, applyToken,
                            mInputWindowCommands, mDesiredPresentTime, mIsAutoTimestamp,
                            {} /*uncacheBuffer - only set in doUncacheBufferTransaction*/,
                            hasListenerCallbacks, listenerCallbacks, mId);
    mId = generateId();

    // Clear the current states and flags
    clear();

    mStatus = NO_ERROR;
    return NO_ERROR;
}

// ---------------------------------------------------------------------------

sp<IBinder> SurfaceComposerClient::createDisplay(const String8& displayName, bool secure) {
    return ComposerService::getComposerService()->createDisplay(displayName,
            secure);
}

void SurfaceComposerClient::destroyDisplay(const sp<IBinder>& display) {
    return ComposerService::getComposerService()->destroyDisplay(display);
}

std::vector<PhysicalDisplayId> SurfaceComposerClient::getPhysicalDisplayIds() {
    return ComposerService::getComposerService()->getPhysicalDisplayIds();
}

status_t SurfaceComposerClient::getPrimaryPhysicalDisplayId(PhysicalDisplayId* id) {
    return ComposerService::getComposerService()->getPrimaryPhysicalDisplayId(id);
}

std::optional<PhysicalDisplayId> SurfaceComposerClient::getInternalDisplayId() {
    return ComposerService::getComposerService()->getInternalDisplayId();
}

sp<IBinder> SurfaceComposerClient::getPhysicalDisplayToken(PhysicalDisplayId displayId) {
    return ComposerService::getComposerService()->getPhysicalDisplayToken(displayId);
}

sp<IBinder> SurfaceComposerClient::getInternalDisplayToken() {
    return ComposerService::getComposerService()->getInternalDisplayToken();
}

void SurfaceComposerClient::Transaction::setAnimationTransaction() {
    mAnimation = true;
}

void SurfaceComposerClient::Transaction::setEarlyWakeupStart() {
    mEarlyWakeupStart = true;
}

void SurfaceComposerClient::Transaction::setEarlyWakeupEnd() {
    mEarlyWakeupEnd = true;
}

layer_state_t* SurfaceComposerClient::Transaction::getLayerState(const sp<SurfaceControl>& sc) {
    auto handle = sc->getLayerStateHandle();

    if (mComposerStates.count(handle) == 0) {
        // we don't have it, add an initialized layer_state to our list
        ComposerState s;

        s.state.surface = handle;
        s.state.layerId = sc->getLayerId();

        mComposerStates[handle] = s;
    }

    return &(mComposerStates[handle].state);
}

void SurfaceComposerClient::Transaction::registerSurfaceControlForCallback(
        const sp<SurfaceControl>& sc) {
    auto& callbackInfo = mListenerCallbacks[TransactionCompletedListener::getIInstance()];
    callbackInfo.surfaceControls.insert(sc);

    TransactionCompletedListener::getInstance()
            ->addSurfaceControlToCallbacks(sc, callbackInfo.callbackIds);
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setPosition(
        const sp<SurfaceControl>& sc, float x, float y) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::ePositionChanged;
    s->x = x;
    s->y = y;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::show(
        const sp<SurfaceControl>& sc) {
    return setFlags(sc, 0, layer_state_t::eLayerHidden);
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::hide(
        const sp<SurfaceControl>& sc) {
    return setFlags(sc, layer_state_t::eLayerHidden, layer_state_t::eLayerHidden);
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setSize(
        const sp<SurfaceControl>& sc, uint32_t w, uint32_t h) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eSizeChanged;
    s->w = w;
    s->h = h;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setLayer(
        const sp<SurfaceControl>& sc, int32_t z) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eLayerChanged;
    s->what &= ~layer_state_t::eRelativeLayerChanged;
    s->z = z;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setRelativeLayer(
        const sp<SurfaceControl>& sc, const sp<SurfaceControl>& relativeTo, int32_t z) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eRelativeLayerChanged;
    s->what &= ~layer_state_t::eLayerChanged;
    s->relativeLayerSurfaceControl = relativeTo;
    s->z = z;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setFlags(
        const sp<SurfaceControl>& sc, uint32_t flags,
        uint32_t mask) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    if ((mask & layer_state_t::eLayerOpaque) || (mask & layer_state_t::eLayerHidden) ||
        (mask & layer_state_t::eLayerSecure) || (mask & layer_state_t::eLayerSkipScreenshot) ||
        (mask & layer_state_t::eEnableBackpressure)) {
        s->what |= layer_state_t::eFlagsChanged;
    }
    s->flags &= ~mask;
    s->flags |= (flags & mask);
    s->mask |= mask;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setTransparentRegionHint(
        const sp<SurfaceControl>& sc,
        const Region& transparentRegion) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eTransparentRegionChanged;
    s->transparentRegion = transparentRegion;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setAlpha(
        const sp<SurfaceControl>& sc, float alpha) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eAlphaChanged;
    s->alpha = alpha;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setLayerStack(
        const sp<SurfaceControl>& sc, uint32_t layerStack) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eLayerStackChanged;
    s->layerStack = layerStack;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setMetadata(
        const sp<SurfaceControl>& sc, uint32_t key, const Parcel& p) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eMetadataChanged;

    s->metadata.mMap[key] = {p.data(), p.data() + p.dataSize()};

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setMatrix(
        const sp<SurfaceControl>& sc, float dsdx, float dtdx,
        float dtdy, float dsdy) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eMatrixChanged;
    layer_state_t::matrix22_t matrix;
    matrix.dsdx = dsdx;
    matrix.dtdx = dtdx;
    matrix.dsdy = dsdy;
    matrix.dtdy = dtdy;
    s->matrix = matrix;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setCrop(
        const sp<SurfaceControl>& sc, const Rect& crop) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eCropChanged;
    s->crop = crop;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setCornerRadius(
        const sp<SurfaceControl>& sc, float cornerRadius) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eCornerRadiusChanged;
    s->cornerRadius = cornerRadius;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setBackgroundBlurRadius(
        const sp<SurfaceControl>& sc, int backgroundBlurRadius) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eBackgroundBlurRadiusChanged;
    s->backgroundBlurRadius = backgroundBlurRadius;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setBlurRegions(
        const sp<SurfaceControl>& sc, const std::vector<BlurRegion>& blurRegions) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eBlurRegionsChanged;
    s->blurRegions = blurRegions;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::reparent(
        const sp<SurfaceControl>& sc, const sp<SurfaceControl>& newParent) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    if (SurfaceControl::isSameSurface(sc, newParent)) {
        return *this;
    }
    s->what |= layer_state_t::eReparent;
    s->parentSurfaceControlForChild = newParent ? newParent->getParentingLayer() : nullptr;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setColor(
        const sp<SurfaceControl>& sc,
        const half3& color) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eColorChanged;
    s->color = color;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setBackgroundColor(
        const sp<SurfaceControl>& sc, const half3& color, float alpha, ui::Dataspace dataspace) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eBackgroundColorChanged;
    s->color = color;
    s->bgColorAlpha = alpha;
    s->bgColorDataspace = dataspace;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setTransform(
        const sp<SurfaceControl>& sc, uint32_t transform) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eTransformChanged;
    s->transform = transform;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction&
SurfaceComposerClient::Transaction::setTransformToDisplayInverse(const sp<SurfaceControl>& sc,
                                                                 bool transformToDisplayInverse) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eTransformToDisplayInverseChanged;
    s->transformToDisplayInverse = transformToDisplayInverse;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setBuffer(
        const sp<SurfaceControl>& sc, const sp<GraphicBuffer>& buffer, const ReleaseCallbackId& id,
        ReleaseBufferCallback callback) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    removeReleaseBufferCallback(s);
    s->what |= layer_state_t::eBufferChanged;
    s->buffer = buffer;
    s->releaseBufferEndpoint = IInterface::asBinder(TransactionCompletedListener::getIInstance());
    if (mIsAutoTimestamp) {
        mDesiredPresentTime = systemTime();
    }
    setReleaseBufferCallback(s, id, callback);

    registerSurfaceControlForCallback(sc);

    mContainsBuffer = true;
    return *this;
}

void SurfaceComposerClient::Transaction::removeReleaseBufferCallback(layer_state_t* s) {
    if (!s->releaseBufferListener) {
        return;
    }

    s->what &= ~static_cast<uint64_t>(layer_state_t::eReleaseBufferListenerChanged);
    s->releaseBufferListener = nullptr;
    auto listener = TransactionCompletedListener::getInstance();
    listener->removeReleaseBufferCallback(s->releaseCallbackId);
    s->releaseCallbackId = ReleaseCallbackId::INVALID_ID;
}

void SurfaceComposerClient::Transaction::setReleaseBufferCallback(layer_state_t* s,
                                                                  const ReleaseCallbackId& id,
                                                                  ReleaseBufferCallback callback) {
    if (!callback) {
        return;
    }

    if (!s->buffer) {
        ALOGW("Transaction::setReleaseBufferCallback"
              "ignored trying to set a callback on a null buffer.");
        return;
    }

    s->what |= layer_state_t::eReleaseBufferListenerChanged;
    s->releaseBufferListener = TransactionCompletedListener::getIInstance();
    s->releaseCallbackId = id;
    auto listener = TransactionCompletedListener::getInstance();
    listener->setReleaseBufferCallback(id, callback);
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setAcquireFence(
        const sp<SurfaceControl>& sc, const sp<Fence>& fence) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eAcquireFenceChanged;
    s->acquireFence = fence;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setDataspace(
        const sp<SurfaceControl>& sc, ui::Dataspace dataspace) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eDataspaceChanged;
    s->dataspace = dataspace;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setHdrMetadata(
        const sp<SurfaceControl>& sc, const HdrMetadata& hdrMetadata) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eHdrMetadataChanged;
    s->hdrMetadata = hdrMetadata;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setSurfaceDamageRegion(
        const sp<SurfaceControl>& sc, const Region& surfaceDamageRegion) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eSurfaceDamageRegionChanged;
    s->surfaceDamageRegion = surfaceDamageRegion;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setApi(
        const sp<SurfaceControl>& sc, int32_t api) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eApiChanged;
    s->api = api;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setSidebandStream(
        const sp<SurfaceControl>& sc, const sp<NativeHandle>& sidebandStream) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eSidebandStreamChanged;
    s->sidebandStream = sidebandStream;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setDesiredPresentTime(
        nsecs_t desiredPresentTime) {
    mDesiredPresentTime = desiredPresentTime;
    mIsAutoTimestamp = false;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setColorSpaceAgnostic(
        const sp<SurfaceControl>& sc, const bool agnostic) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eColorSpaceAgnosticChanged;
    s->colorSpaceAgnostic = agnostic;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction&
SurfaceComposerClient::Transaction::setFrameRateSelectionPriority(const sp<SurfaceControl>& sc,
                                                                  int32_t priority) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eFrameRateSelectionPriority;
    s->frameRateSelectionPriority = priority;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::addTransactionCallback(
        TransactionCompletedCallbackTakesContext callback, void* callbackContext,
        CallbackId::Type callbackType) {
    auto listener = TransactionCompletedListener::getInstance();

    auto callbackWithContext = std::bind(callback, callbackContext, std::placeholders::_1,
                                         std::placeholders::_2, std::placeholders::_3);
    const auto& surfaceControls =
            mListenerCallbacks[TransactionCompletedListener::getIInstance()].surfaceControls;

    CallbackId callbackId =
            listener->addCallbackFunction(callbackWithContext, surfaceControls, callbackType);

    mListenerCallbacks[TransactionCompletedListener::getIInstance()].callbackIds.emplace(
            callbackId);
    return *this;
}

SurfaceComposerClient::Transaction&
SurfaceComposerClient::Transaction::addTransactionCompletedCallback(
        TransactionCompletedCallbackTakesContext callback, void* callbackContext) {
    return addTransactionCallback(callback, callbackContext, CallbackId::Type::ON_COMPLETE);
}

SurfaceComposerClient::Transaction&
SurfaceComposerClient::Transaction::addTransactionCommittedCallback(
        TransactionCompletedCallbackTakesContext callback, void* callbackContext) {
    return addTransactionCallback(callback, callbackContext, CallbackId::Type::ON_COMMIT);
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::notifyProducerDisconnect(
        const sp<SurfaceControl>& sc) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eProducerDisconnect;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setFrameNumber(
        const sp<SurfaceControl>& sc, uint64_t frameNumber) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eFrameNumberChanged;
    s->frameNumber = frameNumber;

    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setInputWindowInfo(
        const sp<SurfaceControl>& sc, const WindowInfo& info) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->windowInfoHandle = new WindowInfoHandle(info);
    s->what |= layer_state_t::eInputInfoChanged;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setFocusedWindow(
        const FocusRequest& request) {
    mInputWindowCommands.focusRequests.push_back(request);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::syncInputWindows() {
    mInputWindowCommands.syncInputWindows = true;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setColorTransform(
    const sp<SurfaceControl>& sc, const mat3& matrix, const vec3& translation) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eColorTransformChanged;
    s->colorTransform = mat4(matrix, translation);

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setGeometry(
        const sp<SurfaceControl>& sc, const Rect& source, const Rect& dst, int transform) {
    setCrop(sc, source);

    int x = dst.left;
    int y = dst.top;

    float sourceWidth = source.getWidth();
    float sourceHeight = source.getHeight();

    float xScale = sourceWidth < 0 ? 1.0f : dst.getWidth() / sourceWidth;
    float yScale = sourceHeight < 0 ? 1.0f : dst.getHeight() / sourceHeight;
    float matrix[4] = {1, 0, 0, 1};

    switch (transform) {
        case NATIVE_WINDOW_TRANSFORM_FLIP_H:
            matrix[0] = -xScale; matrix[1] = 0;
            matrix[2] = 0; matrix[3] = yScale;
            x += source.getWidth();
            break;
        case NATIVE_WINDOW_TRANSFORM_FLIP_V:
            matrix[0] = xScale; matrix[1] = 0;
            matrix[2] = 0; matrix[3] = -yScale;
            y += source.getHeight();
            break;
        case NATIVE_WINDOW_TRANSFORM_ROT_90:
            matrix[0] = 0; matrix[1] = -yScale;
            matrix[2] = xScale; matrix[3] = 0;
            x += source.getHeight();
            break;
        case NATIVE_WINDOW_TRANSFORM_ROT_180:
            matrix[0] = -xScale; matrix[1] = 0;
            matrix[2] = 0; matrix[3] = -yScale;
            x += source.getWidth();
            y += source.getHeight();
            break;
        case NATIVE_WINDOW_TRANSFORM_ROT_270:
            matrix[0] = 0; matrix[1] = yScale;
            matrix[2] = -xScale; matrix[3] = 0;
            y += source.getWidth();
            break;
        default:
            matrix[0] = xScale; matrix[1] = 0;
            matrix[2] = 0; matrix[3] = yScale;
            break;
    }
    setMatrix(sc, matrix[0], matrix[1], matrix[2], matrix[3]);
    float offsetX = xScale * source.left;
    float offsetY = yScale * source.top;
    setPosition(sc, x - offsetX, y - offsetY);

    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setShadowRadius(
        const sp<SurfaceControl>& sc, float shadowRadius) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    s->what |= layer_state_t::eShadowRadiusChanged;
    s->shadowRadius = shadowRadius;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setFrameRate(
        const sp<SurfaceControl>& sc, float frameRate, int8_t compatibility,
        int8_t changeFrameRateStrategy) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }
    // Allow privileged values as well here, those will be ignored by SF if
    // the caller is not privileged
    if (!ValidateFrameRate(frameRate, compatibility, changeFrameRateStrategy,
                           "Transaction::setFrameRate",
                           /*privileged=*/true)) {
        mStatus = BAD_VALUE;
        return *this;
    }
    s->what |= layer_state_t::eFrameRateChanged;
    s->frameRate = frameRate;
    s->frameRateCompatibility = compatibility;
    s->changeFrameRateStrategy = changeFrameRateStrategy;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setFixedTransformHint(
        const sp<SurfaceControl>& sc, int32_t fixedTransformHint) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    const ui::Transform::RotationFlags transform = fixedTransformHint == -1
            ? ui::Transform::ROT_INVALID
            : ui::Transform::toRotationFlags(static_cast<ui::Rotation>(fixedTransformHint));
    s->what |= layer_state_t::eFixedTransformHintChanged;
    s->fixedTransformHint = transform;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setFrameTimelineInfo(
        const FrameTimelineInfo& frameTimelineInfo) {
    mFrameTimelineInfo.merge(frameTimelineInfo);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setAutoRefresh(
        const sp<SurfaceControl>& sc, bool autoRefresh) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eAutoRefreshChanged;
    s->autoRefresh = autoRefresh;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setTrustedOverlay(
        const sp<SurfaceControl>& sc, bool isTrustedOverlay) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eTrustedOverlayChanged;
    s->isTrustedOverlay = isTrustedOverlay;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setApplyToken(
        const sp<IBinder>& applyToken) {
    mApplyToken = applyToken;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setStretchEffect(
    const sp<SurfaceControl>& sc, const StretchEffect& stretchEffect) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eStretchChanged;
    s->stretchEffect = stretchEffect;
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setBufferCrop(
        const sp<SurfaceControl>& sc, const Rect& bufferCrop) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eBufferCropChanged;
    s->bufferCrop = bufferCrop;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setDestinationFrame(
        const sp<SurfaceControl>& sc, const Rect& destinationFrame) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eDestinationFrameChanged;
    s->destinationFrame = destinationFrame;

    registerSurfaceControlForCallback(sc);
    return *this;
}

SurfaceComposerClient::Transaction& SurfaceComposerClient::Transaction::setDropInputMode(
        const sp<SurfaceControl>& sc, gui::DropInputMode mode) {
    layer_state_t* s = getLayerState(sc);
    if (!s) {
        mStatus = BAD_INDEX;
        return *this;
    }

    s->what |= layer_state_t::eDropInputModeChanged;
    s->dropInputMode = mode;

    registerSurfaceControlForCallback(sc);
    return *this;
}

// ---------------------------------------------------------------------------

DisplayState& SurfaceComposerClient::Transaction::getDisplayState(const sp<IBinder>& token) {
    DisplayState s;
    s.token = token;
    ssize_t index = mDisplayStates.indexOf(s);
    if (index < 0) {
        // we don't have it, add an initialized layer_state to our list
        s.what = 0;
        index = mDisplayStates.add(s);
    }
    return mDisplayStates.editItemAt(static_cast<size_t>(index));
}

status_t SurfaceComposerClient::Transaction::setDisplaySurface(const sp<IBinder>& token,
        const sp<IGraphicBufferProducer>& bufferProducer) {
    if (bufferProducer.get() != nullptr) {
        // Make sure that composition can never be stalled by a virtual display
        // consumer that isn't processing buffers fast enough.
        status_t err = bufferProducer->setAsyncMode(true);
        if (err != NO_ERROR) {
            ALOGE("Composer::setDisplaySurface Failed to enable async mode on the "
                    "BufferQueue. This BufferQueue cannot be used for virtual "
                    "display. (%d)", err);
            return err;
        }
    }
    DisplayState& s(getDisplayState(token));
    s.surface = bufferProducer;
    s.what |= DisplayState::eSurfaceChanged;
    return NO_ERROR;
}

void SurfaceComposerClient::Transaction::setDisplayLayerStack(const sp<IBinder>& token,
        uint32_t layerStack) {
    DisplayState& s(getDisplayState(token));
    s.layerStack = layerStack;
    s.what |= DisplayState::eLayerStackChanged;
}

void SurfaceComposerClient::Transaction::setDisplayFlags(const sp<IBinder>& token, uint32_t flags) {
    DisplayState& s(getDisplayState(token));
    s.flags = flags;
    s.what |= DisplayState::eFlagsChanged;
}

void SurfaceComposerClient::Transaction::setDisplayProjection(const sp<IBinder>& token,
                                                              ui::Rotation orientation,
                                                              const Rect& layerStackRect,
                                                              const Rect& displayRect) {
    DisplayState& s(getDisplayState(token));
    s.orientation = orientation;
    s.layerStackSpaceRect = layerStackRect;
    s.orientedDisplaySpaceRect = displayRect;
    s.what |= DisplayState::eDisplayProjectionChanged;
    mForceSynchronous = true; // TODO: do we actually still need this?
}

void SurfaceComposerClient::Transaction::setDisplaySize(const sp<IBinder>& token, uint32_t width, uint32_t height) {
    DisplayState& s(getDisplayState(token));
    s.width = width;
    s.height = height;
    s.what |= DisplayState::eDisplaySizeChanged;
}

// ---------------------------------------------------------------------------

SurfaceComposerClient::SurfaceComposerClient() : mStatus(NO_INIT) {}

SurfaceComposerClient::SurfaceComposerClient(const sp<ISurfaceComposerClient>& client)
      : mStatus(NO_ERROR), mClient(client) {}

void SurfaceComposerClient::onFirstRef() {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    if (sf != nullptr && mStatus == NO_INIT) {
        sp<ISurfaceComposerClient> conn;
        conn = sf->createConnection();
        if (conn != nullptr) {
            mClient = conn;
            mStatus = NO_ERROR;
        }
    }
}

SurfaceComposerClient::~SurfaceComposerClient() {
    dispose();
}

status_t SurfaceComposerClient::initCheck() const {
    return mStatus;
}

sp<IBinder> SurfaceComposerClient::connection() const {
    return IInterface::asBinder(mClient);
}

status_t SurfaceComposerClient::linkToComposerDeath(
        const sp<IBinder::DeathRecipient>& recipient,
        void* cookie, uint32_t flags) {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    return IInterface::asBinder(sf)->linkToDeath(recipient, cookie, flags);
}

void SurfaceComposerClient::dispose() {
    // this can be called more than once.
    sp<ISurfaceComposerClient> client;
    Mutex::Autolock _lm(mLock);
    if (mClient != nullptr) {
        client = mClient; // hold ref while lock is held
        mClient.clear();
    }
    mStatus = NO_INIT;
}

sp<SurfaceControl> SurfaceComposerClient::createSurface(const String8& name, uint32_t w, uint32_t h,
                                                        PixelFormat format, uint32_t flags,
                                                        const sp<IBinder>& parentHandle,
                                                        LayerMetadata metadata,
                                                        uint32_t* outTransformHint) {
    sp<SurfaceControl> s;
    createSurfaceChecked(name, w, h, format, &s, flags, parentHandle, std::move(metadata),
                         outTransformHint);
    return s;
}

sp<SurfaceControl> SurfaceComposerClient::createWithSurfaceParent(const String8& name, uint32_t w,
                                                                  uint32_t h, PixelFormat format,
                                                                  uint32_t flags, Surface* parent,
                                                                  LayerMetadata metadata,
                                                                  uint32_t* outTransformHint) {
    sp<SurfaceControl> sur;
    status_t err = mStatus;

    if (mStatus == NO_ERROR) {
        sp<IBinder> handle;
        sp<IGraphicBufferProducer> parentGbp = parent->getIGraphicBufferProducer();
        sp<IGraphicBufferProducer> gbp;

        uint32_t transformHint = 0;
        int32_t id = -1;
        err = mClient->createWithSurfaceParent(name, w, h, format, flags, parentGbp,
                                               std::move(metadata), &handle, &gbp, &id,
                                               &transformHint);
        if (outTransformHint) {
            *outTransformHint = transformHint;
        }
        ALOGE_IF(err, "SurfaceComposerClient::createWithSurfaceParent error %s", strerror(-err));
        if (err == NO_ERROR) {
            return new SurfaceControl(this, handle, gbp, id, transformHint);
        }
    }
    return nullptr;
}

status_t SurfaceComposerClient::createSurfaceChecked(const String8& name, uint32_t w, uint32_t h,
                                                     PixelFormat format,
                                                     sp<SurfaceControl>* outSurface, uint32_t flags,
                                                     const sp<IBinder>& parentHandle,
                                                     LayerMetadata metadata,
                                                     uint32_t* outTransformHint) {
    sp<SurfaceControl> sur;
    status_t err = mStatus;

    if (mStatus == NO_ERROR) {
        sp<IBinder> handle;
        sp<IGraphicBufferProducer> gbp;

        uint32_t transformHint = 0;
        int32_t id = -1;
        err = mClient->createSurface(name, w, h, format, flags, parentHandle, std::move(metadata),
                                     &handle, &gbp, &id, &transformHint);

        if (outTransformHint) {
            *outTransformHint = transformHint;
        }
        ALOGE_IF(err, "SurfaceComposerClient::createSurface error %s", strerror(-err));
        if (err == NO_ERROR) {
            *outSurface =
                    new SurfaceControl(this, handle, gbp, id, w, h, format, transformHint, flags);
        }
    }
    return err;
}

sp<SurfaceControl> SurfaceComposerClient::mirrorSurface(SurfaceControl* mirrorFromSurface) {
    if (mirrorFromSurface == nullptr) {
        return nullptr;
    }

    sp<IBinder> handle;
    sp<IBinder> mirrorFromHandle = mirrorFromSurface->getHandle();
    int32_t layer_id = -1;
    status_t err = mClient->mirrorSurface(mirrorFromHandle, &handle, &layer_id);
    if (err == NO_ERROR) {
        return new SurfaceControl(this, handle, nullptr, layer_id, true /* owned */);
    }
    return nullptr;
}

status_t SurfaceComposerClient::clearLayerFrameStats(const sp<IBinder>& token) const {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    return mClient->clearLayerFrameStats(token);
}

status_t SurfaceComposerClient::getLayerFrameStats(const sp<IBinder>& token,
        FrameStats* outStats) const {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    return mClient->getLayerFrameStats(token, outStats);
}

// ----------------------------------------------------------------------------

status_t SurfaceComposerClient::enableVSyncInjections(bool enable) {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    return sf->enableVSyncInjections(enable);
}

status_t SurfaceComposerClient::injectVSync(nsecs_t when) {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    return sf->injectVSync(when);
}

status_t SurfaceComposerClient::getDisplayState(const sp<IBinder>& display,
                                                ui::DisplayState* state) {
    return ComposerService::getComposerService()->getDisplayState(display, state);
}

status_t SurfaceComposerClient::getStaticDisplayInfo(const sp<IBinder>& display,
                                                     ui::StaticDisplayInfo* info) {
    return ComposerService::getComposerService()->getStaticDisplayInfo(display, info);
}

status_t SurfaceComposerClient::getDynamicDisplayInfo(const sp<IBinder>& display,
                                                      ui::DynamicDisplayInfo* info) {
    return ComposerService::getComposerService()->getDynamicDisplayInfo(display, info);
}

status_t SurfaceComposerClient::getActiveDisplayMode(const sp<IBinder>& display,
                                                     ui::DisplayMode* mode) {
    ui::DynamicDisplayInfo info;
    status_t result = getDynamicDisplayInfo(display, &info);
    if (result != NO_ERROR) {
        return result;
    }

    if (const auto activeMode = info.getActiveDisplayMode()) {
        *mode = *activeMode;
        return NO_ERROR;
    }

    ALOGE("Active display mode not found.");
    return NAME_NOT_FOUND;
}

status_t SurfaceComposerClient::setDesiredDisplayModeSpecs(
        const sp<IBinder>& displayToken, ui::DisplayModeId defaultMode, bool allowGroupSwitching,
        float primaryRefreshRateMin, float primaryRefreshRateMax, float appRequestRefreshRateMin,
        float appRequestRefreshRateMax) {
    return ComposerService::getComposerService()
            ->setDesiredDisplayModeSpecs(displayToken, defaultMode, allowGroupSwitching,
                                         primaryRefreshRateMin, primaryRefreshRateMax,
                                         appRequestRefreshRateMin, appRequestRefreshRateMax);
}

status_t SurfaceComposerClient::getDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                                           ui::DisplayModeId* outDefaultMode,
                                                           bool* outAllowGroupSwitching,
                                                           float* outPrimaryRefreshRateMin,
                                                           float* outPrimaryRefreshRateMax,
                                                           float* outAppRequestRefreshRateMin,
                                                           float* outAppRequestRefreshRateMax) {
    return ComposerService::getComposerService()
            ->getDesiredDisplayModeSpecs(displayToken, outDefaultMode, outAllowGroupSwitching,
                                         outPrimaryRefreshRateMin, outPrimaryRefreshRateMax,
                                         outAppRequestRefreshRateMin, outAppRequestRefreshRateMax);
}

status_t SurfaceComposerClient::getDisplayNativePrimaries(const sp<IBinder>& display,
        ui::DisplayPrimaries& outPrimaries) {
    return ComposerService::getComposerService()->getDisplayNativePrimaries(display, outPrimaries);
}

status_t SurfaceComposerClient::setActiveColorMode(const sp<IBinder>& display,
        ColorMode colorMode) {
    return ComposerService::getComposerService()->setActiveColorMode(display, colorMode);
}

void SurfaceComposerClient::setAutoLowLatencyMode(const sp<IBinder>& display, bool on) {
    ComposerService::getComposerService()->setAutoLowLatencyMode(display, on);
}

void SurfaceComposerClient::setGameContentType(const sp<IBinder>& display, bool on) {
    ComposerService::getComposerService()->setGameContentType(display, on);
}

void SurfaceComposerClient::setDisplayPowerMode(const sp<IBinder>& token,
        int mode) {
    ComposerService::getComposerService()->setPowerMode(token, mode);
}

status_t SurfaceComposerClient::getCompositionPreference(
        ui::Dataspace* defaultDataspace, ui::PixelFormat* defaultPixelFormat,
        ui::Dataspace* wideColorGamutDataspace, ui::PixelFormat* wideColorGamutPixelFormat) {
    return ComposerService::getComposerService()
            ->getCompositionPreference(defaultDataspace, defaultPixelFormat,
                                       wideColorGamutDataspace, wideColorGamutPixelFormat);
}

bool SurfaceComposerClient::getProtectedContentSupport() {
    bool supported = false;
    ComposerService::getComposerService()->getProtectedContentSupport(&supported);
    return supported;
}

status_t SurfaceComposerClient::clearAnimationFrameStats() {
    return ComposerService::getComposerService()->clearAnimationFrameStats();
}

status_t SurfaceComposerClient::getAnimationFrameStats(FrameStats* outStats) {
    return ComposerService::getComposerService()->getAnimationFrameStats(outStats);
}

status_t SurfaceComposerClient::overrideHdrTypes(const sp<IBinder>& display,
                                                 const std::vector<ui::Hdr>& hdrTypes) {
    return ComposerService::getComposerService()->overrideHdrTypes(display, hdrTypes);
}

status_t SurfaceComposerClient::onPullAtom(const int32_t atomId, std::string* outData,
                                           bool* success) {
    return ComposerService::getComposerService()->onPullAtom(atomId, outData, success);
}

status_t SurfaceComposerClient::getDisplayedContentSamplingAttributes(const sp<IBinder>& display,
                                                                      ui::PixelFormat* outFormat,
                                                                      ui::Dataspace* outDataspace,
                                                                      uint8_t* outComponentMask) {
    return ComposerService::getComposerService()
            ->getDisplayedContentSamplingAttributes(display, outFormat, outDataspace,
                                                    outComponentMask);
}

status_t SurfaceComposerClient::setDisplayContentSamplingEnabled(const sp<IBinder>& display,
                                                                 bool enable, uint8_t componentMask,
                                                                 uint64_t maxFrames) {
    return ComposerService::getComposerService()->setDisplayContentSamplingEnabled(display, enable,
                                                                                   componentMask,
                                                                                   maxFrames);
}

status_t SurfaceComposerClient::getDisplayedContentSample(const sp<IBinder>& display,
                                                          uint64_t maxFrames, uint64_t timestamp,
                                                          DisplayedFrameStats* outStats) {
    return ComposerService::getComposerService()->getDisplayedContentSample(display, maxFrames,
                                                                            timestamp, outStats);
}

status_t SurfaceComposerClient::isWideColorDisplay(const sp<IBinder>& display,
                                                   bool* outIsWideColorDisplay) {
    return ComposerService::getComposerService()->isWideColorDisplay(display,
                                                                     outIsWideColorDisplay);
}

status_t SurfaceComposerClient::addRegionSamplingListener(
        const Rect& samplingArea, const sp<IBinder>& stopLayerHandle,
        const sp<IRegionSamplingListener>& listener) {
    return ComposerService::getComposerService()->addRegionSamplingListener(samplingArea,
                                                                            stopLayerHandle,
                                                                            listener);
}

status_t SurfaceComposerClient::removeRegionSamplingListener(
        const sp<IRegionSamplingListener>& listener) {
    return ComposerService::getComposerService()->removeRegionSamplingListener(listener);
}

status_t SurfaceComposerClient::addFpsListener(int32_t taskId,
                                               const sp<gui::IFpsListener>& listener) {
    return ComposerService::getComposerService()->addFpsListener(taskId, listener);
}

status_t SurfaceComposerClient::removeFpsListener(const sp<gui::IFpsListener>& listener) {
    return ComposerService::getComposerService()->removeFpsListener(listener);
}

status_t SurfaceComposerClient::addTunnelModeEnabledListener(
        const sp<gui::ITunnelModeEnabledListener>& listener) {
    return ComposerService::getComposerService()->addTunnelModeEnabledListener(listener);
}

status_t SurfaceComposerClient::removeTunnelModeEnabledListener(
        const sp<gui::ITunnelModeEnabledListener>& listener) {
    return ComposerService::getComposerService()->removeTunnelModeEnabledListener(listener);
}

bool SurfaceComposerClient::getDisplayBrightnessSupport(const sp<IBinder>& displayToken) {
    bool support = false;
    ComposerService::getComposerService()->getDisplayBrightnessSupport(displayToken, &support);
    return support;
}

status_t SurfaceComposerClient::setDisplayBrightness(const sp<IBinder>& displayToken,
                                                     const gui::DisplayBrightness& brightness) {
    return ComposerService::getComposerService()->setDisplayBrightness(displayToken, brightness);
}

status_t SurfaceComposerClient::addHdrLayerInfoListener(
        const sp<IBinder>& displayToken, const sp<gui::IHdrLayerInfoListener>& listener) {
    return ComposerService::getComposerService()->addHdrLayerInfoListener(displayToken, listener);
}

status_t SurfaceComposerClient::removeHdrLayerInfoListener(
        const sp<IBinder>& displayToken, const sp<gui::IHdrLayerInfoListener>& listener) {
    return ComposerService::getComposerService()->removeHdrLayerInfoListener(displayToken,
                                                                             listener);
}

status_t SurfaceComposerClient::notifyPowerBoost(int32_t boostId) {
    return ComposerService::getComposerService()->notifyPowerBoost(boostId);
}

status_t SurfaceComposerClient::setGlobalShadowSettings(const half4& ambientColor,
                                                        const half4& spotColor, float lightPosY,
                                                        float lightPosZ, float lightRadius) {
    return ComposerService::getComposerService()->setGlobalShadowSettings(ambientColor, spotColor,
                                                                          lightPosY, lightPosZ,
                                                                          lightRadius);
}

int SurfaceComposerClient::getGPUContextPriority() {
    return ComposerService::getComposerService()->getGPUContextPriority();
}

status_t SurfaceComposerClient::addWindowInfosListener(
        const sp<WindowInfosListener>& windowInfosListener) {
    return WindowInfosListenerReporter::getInstance()
            ->addWindowInfosListener(windowInfosListener, ComposerService::getComposerService());
}

status_t SurfaceComposerClient::removeWindowInfosListener(
        const sp<WindowInfosListener>& windowInfosListener) {
    return WindowInfosListenerReporter::getInstance()
            ->removeWindowInfosListener(windowInfosListener, ComposerService::getComposerService());
}

// ----------------------------------------------------------------------------

status_t ScreenshotClient::captureDisplay(const DisplayCaptureArgs& captureArgs,
                                          const sp<IScreenCaptureListener>& captureListener) {
    sp<ISurfaceComposer> s(ComposerService::getComposerService());
    if (s == nullptr) return NO_INIT;

    return s->captureDisplay(captureArgs, captureListener);
}

status_t ScreenshotClient::captureDisplay(uint64_t displayOrLayerStack,
                                          const sp<IScreenCaptureListener>& captureListener) {
    sp<ISurfaceComposer> s(ComposerService::getComposerService());
    if (s == nullptr) return NO_INIT;

    return s->captureDisplay(displayOrLayerStack, captureListener);
}

status_t ScreenshotClient::captureLayers(const LayerCaptureArgs& captureArgs,
                                         const sp<IScreenCaptureListener>& captureListener) {
    sp<ISurfaceComposer> s(ComposerService::getComposerService());
    if (s == nullptr) return NO_INIT;

    return s->captureLayers(captureArgs, captureListener);
}

} // namespace android
