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

#pragma once

#include <android-base/thread_annotations.h>
#include <binder/IBinder.h>
#include <gui/LayerState.h>
#include <renderengine/RenderEngine.h>
#include <ui/GraphicBuffer.h>
#include <utils/RefBase.h>
#include <utils/Singleton.h>

#include <map>
#include <mutex>
#include <set>
#include <unordered_map>

#define BUFFER_CACHE_MAX_SIZE 64

namespace android {

class ClientCache : public Singleton<ClientCache> {
public:
    ClientCache();

    bool add(const client_cache_t& cacheId, const sp<GraphicBuffer>& buffer);
    void erase(const client_cache_t& cacheId);

    std::shared_ptr<renderengine::ExternalTexture> get(const client_cache_t& cacheId);

    // Always called immediately after setup. Will be set to non-null, and then should never be
    // called again.
    void setRenderEngine(renderengine::RenderEngine* renderEngine) { mRenderEngine = renderEngine; }

    void removeProcess(const wp<IBinder>& processToken);

    class ErasedRecipient : public virtual RefBase {
    public:
        virtual void bufferErased(const client_cache_t& clientCacheId) = 0;
    };

    bool registerErasedRecipient(const client_cache_t& cacheId,
                                 const wp<ErasedRecipient>& recipient);
    void unregisterErasedRecipient(const client_cache_t& cacheId,
                                   const wp<ErasedRecipient>& recipient);

    void dump(std::string& result);

private:
    std::mutex mMutex;

    struct ClientCacheBuffer {
        std::shared_ptr<renderengine::ExternalTexture> buffer;
        std::set<wp<ErasedRecipient>> recipients;
    };
    std::map<wp<IBinder> /*caching process*/,
             std::pair<sp<IBinder> /*strong ref to caching process*/,
                       std::unordered_map<uint64_t /*cache id*/, ClientCacheBuffer>>>
            mBuffers GUARDED_BY(mMutex);

    class CacheDeathRecipient : public IBinder::DeathRecipient {
    public:
        void binderDied(const wp<IBinder>& who) override;
    };

    sp<CacheDeathRecipient> mDeathRecipient;
    renderengine::RenderEngine* mRenderEngine = nullptr;

    bool getBuffer(const client_cache_t& cacheId, ClientCacheBuffer** outClientCacheBuffer)
            REQUIRES(mMutex);
};

}; // namespace android
