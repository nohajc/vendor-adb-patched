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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "ClientCache"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <cinttypes>

#include "ClientCache.h"

namespace android {

using base::StringAppendF;

ANDROID_SINGLETON_STATIC_INSTANCE(ClientCache);

ClientCache::ClientCache() : mDeathRecipient(new CacheDeathRecipient) {}

bool ClientCache::getBuffer(const client_cache_t& cacheId,
                            ClientCacheBuffer** outClientCacheBuffer) {
    auto& [processToken, id] = cacheId;
    if (processToken == nullptr) {
        ALOGE("failed to get buffer, invalid (nullptr) process token");
        return false;
    }
    auto it = mBuffers.find(processToken);
    if (it == mBuffers.end()) {
        ALOGE("failed to get buffer, invalid process token");
        return false;
    }

    auto& processBuffers = it->second.second;

    auto bufItr = processBuffers.find(id);
    if (bufItr == processBuffers.end()) {
        ALOGV("failed to get buffer, invalid buffer id");
        return false;
    }

    ClientCacheBuffer& buf = bufItr->second;
    *outClientCacheBuffer = &buf;
    return true;
}

bool ClientCache::add(const client_cache_t& cacheId, const sp<GraphicBuffer>& buffer) {
    auto& [processToken, id] = cacheId;
    if (processToken == nullptr) {
        ALOGE("failed to cache buffer: invalid process token");
        return false;
    }

    if (!buffer) {
        ALOGE("failed to cache buffer: invalid buffer");
        return false;
    }

    std::lock_guard lock(mMutex);
    sp<IBinder> token;

    // If this is a new process token, set a death recipient. If the client process dies, we will
    // get a callback through binderDied.
    auto it = mBuffers.find(processToken);
    if (it == mBuffers.end()) {
        token = processToken.promote();
        if (!token) {
            ALOGE("failed to cache buffer: invalid token");
            return false;
        }

        status_t err = token->linkToDeath(mDeathRecipient);
        if (err != NO_ERROR) {
            ALOGE("failed to cache buffer: could not link to death");
            return false;
        }
        auto [itr, success] =
                mBuffers.emplace(processToken,
                                 std::make_pair(token,
                                                std::unordered_map<uint64_t, ClientCacheBuffer>()));
        LOG_ALWAYS_FATAL_IF(!success, "failed to insert new process into client cache");
        it = itr;
    }

    auto& processBuffers = it->second.second;

    if (processBuffers.size() > BUFFER_CACHE_MAX_SIZE) {
        ALOGE("failed to cache buffer: cache is full");
        return false;
    }

    LOG_ALWAYS_FATAL_IF(mRenderEngine == nullptr,
                        "Attempted to build the ClientCache before a RenderEngine instance was "
                        "ready!");
    processBuffers[id].buffer = std::make_shared<
            renderengine::ExternalTexture>(buffer, *mRenderEngine,
                                           renderengine::ExternalTexture::Usage::READABLE);
    return true;
}

void ClientCache::erase(const client_cache_t& cacheId) {
    auto& [processToken, id] = cacheId;
    std::vector<sp<ErasedRecipient>> pendingErase;
    {
        std::lock_guard lock(mMutex);
        ClientCacheBuffer* buf = nullptr;
        if (!getBuffer(cacheId, &buf)) {
            ALOGE("failed to erase buffer, could not retrieve buffer");
            return;
        }

        for (auto& recipient : buf->recipients) {
            sp<ErasedRecipient> erasedRecipient = recipient.promote();
            if (erasedRecipient) {
                pendingErase.push_back(erasedRecipient);
            }
        }

        mBuffers[processToken].second.erase(id);
    }

    for (auto& recipient : pendingErase) {
        recipient->bufferErased(cacheId);
    }
}

std::shared_ptr<renderengine::ExternalTexture> ClientCache::get(const client_cache_t& cacheId) {
    std::lock_guard lock(mMutex);

    ClientCacheBuffer* buf = nullptr;
    if (!getBuffer(cacheId, &buf)) {
        ALOGE("failed to get buffer, could not retrieve buffer");
        return nullptr;
    }

    return buf->buffer;
}

bool ClientCache::registerErasedRecipient(const client_cache_t& cacheId,
                                          const wp<ErasedRecipient>& recipient) {
    std::lock_guard lock(mMutex);

    ClientCacheBuffer* buf = nullptr;
    if (!getBuffer(cacheId, &buf)) {
        ALOGV("failed to register erased recipient, could not retrieve buffer");
        return false;
    }
    buf->recipients.insert(recipient);
    return true;
}

void ClientCache::unregisterErasedRecipient(const client_cache_t& cacheId,
                                            const wp<ErasedRecipient>& recipient) {
    std::lock_guard lock(mMutex);

    ClientCacheBuffer* buf = nullptr;
    if (!getBuffer(cacheId, &buf)) {
        ALOGE("failed to unregister erased recipient");
        return;
    }

    buf->recipients.erase(recipient);
}

void ClientCache::removeProcess(const wp<IBinder>& processToken) {
    std::vector<std::pair<sp<ErasedRecipient>, client_cache_t>> pendingErase;
    {
        if (processToken == nullptr) {
            ALOGE("failed to remove process, invalid (nullptr) process token");
            return;
        }
        std::lock_guard lock(mMutex);
        auto itr = mBuffers.find(processToken);
        if (itr == mBuffers.end()) {
            ALOGE("failed to remove process, could not find process");
            return;
        }

        for (auto& [id, clientCacheBuffer] : itr->second.second) {
            client_cache_t cacheId = {processToken, id};
            for (auto& recipient : clientCacheBuffer.recipients) {
                sp<ErasedRecipient> erasedRecipient = recipient.promote();
                if (erasedRecipient) {
                    pendingErase.emplace_back(erasedRecipient, cacheId);
                }
            }
        }
        mBuffers.erase(itr);
    }

    for (auto& [recipient, cacheId] : pendingErase) {
        recipient->bufferErased(cacheId);
    }
}

void ClientCache::CacheDeathRecipient::binderDied(const wp<IBinder>& who) {
    ClientCache::getInstance().removeProcess(who);
}

void ClientCache::dump(std::string& result) {
    std::lock_guard lock(mMutex);
    for (auto i : mBuffers) {
        const sp<IBinder>& cacheOwner = i.second.first;
        StringAppendF(&result," Cache owner: %p\n", cacheOwner.get());
        auto &buffers = i.second.second;
        for (auto& [id, clientCacheBuffer] : buffers) {
            StringAppendF(&result, "\t ID: %d, Width/Height: %d,%d\n", (int)id,
                          (int)clientCacheBuffer.buffer->getBuffer()->getWidth(),
                          (int)clientCacheBuffer.buffer->getBuffer()->getHeight());
        }
    }
}

}; // namespace android
