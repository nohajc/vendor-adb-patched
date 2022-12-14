/*
 * Copyright 2020 The Android Open Source Project
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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "RenderEngineThreaded.h"

#include <sched.h>
#include <chrono>
#include <future>

#include <android-base/stringprintf.h>
#include <private/gui/SyncFeatures.h>
#include <processgroup/processgroup.h>
#include <utils/Trace.h>

#include "gl/GLESRenderEngine.h"

using namespace std::chrono_literals;

namespace android {
namespace renderengine {
namespace threaded {

std::unique_ptr<RenderEngineThreaded> RenderEngineThreaded::create(CreateInstanceFactory factory,
                                                                   RenderEngineType type) {
    return std::make_unique<RenderEngineThreaded>(std::move(factory), type);
}

RenderEngineThreaded::RenderEngineThreaded(CreateInstanceFactory factory, RenderEngineType type)
      : RenderEngine(type) {
    ATRACE_CALL();

    std::lock_guard lockThread(mThreadMutex);
    mThread = std::thread(&RenderEngineThreaded::threadMain, this, factory);
}

RenderEngineThreaded::~RenderEngineThreaded() {
    mRunning = false;
    mCondition.notify_one();

    if (mThread.joinable()) {
        mThread.join();
    }
}

status_t RenderEngineThreaded::setSchedFifo(bool enabled) {
    static constexpr int kFifoPriority = 2;
    static constexpr int kOtherPriority = 0;

    struct sched_param param = {0};
    int sched_policy;
    if (enabled) {
        sched_policy = SCHED_FIFO;
        param.sched_priority = kFifoPriority;
    } else {
        sched_policy = SCHED_OTHER;
        param.sched_priority = kOtherPriority;
    }

    if (sched_setscheduler(0, sched_policy, &param) != 0) {
        return -errno;
    }
    return NO_ERROR;
}

// NO_THREAD_SAFETY_ANALYSIS is because std::unique_lock presently lacks thread safety annotations.
void RenderEngineThreaded::threadMain(CreateInstanceFactory factory) NO_THREAD_SAFETY_ANALYSIS {
    ATRACE_CALL();

    if (!SetTaskProfiles(0, {"SFRenderEnginePolicy"})) {
        ALOGW("Failed to set render-engine task profile!");
    }

    if (setSchedFifo(true) != NO_ERROR) {
        ALOGW("Couldn't set SCHED_FIFO");
    }

    mRenderEngine = factory();
    mIsProtected = mRenderEngine->isProtected();

    pthread_setname_np(pthread_self(), mThreadName);

    {
        std::scoped_lock lock(mInitializedMutex);
        mIsInitialized = true;
    }
    mInitializedCondition.notify_all();

    while (mRunning) {
        const auto getNextTask = [this]() -> std::optional<Work> {
            std::scoped_lock lock(mThreadMutex);
            if (!mFunctionCalls.empty()) {
                Work task = mFunctionCalls.front();
                mFunctionCalls.pop();
                return std::make_optional<Work>(task);
            }
            return std::nullopt;
        };

        const auto task = getNextTask();

        if (task) {
            (*task)(*mRenderEngine);
        }

        std::unique_lock<std::mutex> lock(mThreadMutex);
        mCondition.wait(lock, [this]() REQUIRES(mThreadMutex) {
            return !mRunning || !mFunctionCalls.empty();
        });
    }

    // we must release the RenderEngine on the thread that created it
    mRenderEngine.reset();
}

void RenderEngineThreaded::waitUntilInitialized() const {
    std::unique_lock<std::mutex> lock(mInitializedMutex);
    mInitializedCondition.wait(lock, [=] { return mIsInitialized; });
}

std::future<void> RenderEngineThreaded::primeCache() {
    const auto resultPromise = std::make_shared<std::promise<void>>();
    std::future<void> resultFuture = resultPromise->get_future();
    ATRACE_CALL();
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([resultPromise](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::primeCache");
            if (setSchedFifo(false) != NO_ERROR) {
                ALOGW("Couldn't set SCHED_OTHER for primeCache");
            }

            instance.primeCache();
            resultPromise->set_value();

            if (setSchedFifo(true) != NO_ERROR) {
                ALOGW("Couldn't set SCHED_FIFO for primeCache");
            }
        });
    }
    mCondition.notify_one();

    return resultFuture;
}

void RenderEngineThreaded::dump(std::string& result) {
    std::promise<std::string> resultPromise;
    std::future<std::string> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, &result](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::dump");
            std::string localResult = result;
            instance.dump(localResult);
            resultPromise.set_value(std::move(localResult));
        });
    }
    mCondition.notify_one();
    // Note: This is an rvalue.
    result.assign(resultFuture.get());
}

void RenderEngineThreaded::genTextures(size_t count, uint32_t* names) {
    ATRACE_CALL();
    // This is a no-op in SkiaRenderEngine.
    if (getRenderEngineType() != RenderEngineType::THREADED) {
        return;
    }
    std::promise<void> resultPromise;
    std::future<void> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, count, names](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::genTextures");
            instance.genTextures(count, names);
            resultPromise.set_value();
        });
    }
    mCondition.notify_one();
    resultFuture.wait();
}

void RenderEngineThreaded::deleteTextures(size_t count, uint32_t const* names) {
    ATRACE_CALL();
    // This is a no-op in SkiaRenderEngine.
    if (getRenderEngineType() != RenderEngineType::THREADED) {
        return;
    }
    std::promise<void> resultPromise;
    std::future<void> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, count, &names](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::deleteTextures");
            instance.deleteTextures(count, names);
            resultPromise.set_value();
        });
    }
    mCondition.notify_one();
    resultFuture.wait();
}

void RenderEngineThreaded::mapExternalTextureBuffer(const sp<GraphicBuffer>& buffer,
                                                    bool isRenderable) {
    ATRACE_CALL();
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([=](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::mapExternalTextureBuffer");
            instance.mapExternalTextureBuffer(buffer, isRenderable);
        });
    }
    mCondition.notify_one();
}

void RenderEngineThreaded::unmapExternalTextureBuffer(const sp<GraphicBuffer>& buffer) {
    ATRACE_CALL();
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([=](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::unmapExternalTextureBuffer");
            instance.unmapExternalTextureBuffer(buffer);
        });
    }
    mCondition.notify_one();
}

size_t RenderEngineThreaded::getMaxTextureSize() const {
    waitUntilInitialized();
    return mRenderEngine->getMaxTextureSize();
}

size_t RenderEngineThreaded::getMaxViewportDims() const {
    waitUntilInitialized();
    return mRenderEngine->getMaxViewportDims();
}

bool RenderEngineThreaded::isProtected() const {
    waitUntilInitialized();
    std::lock_guard lock(mThreadMutex);
    return mIsProtected;
}

bool RenderEngineThreaded::supportsProtectedContent() const {
    waitUntilInitialized();
    return mRenderEngine->supportsProtectedContent();
}

void RenderEngineThreaded::useProtectedContext(bool useProtectedContext) {
    if (isProtected() == useProtectedContext ||
        (useProtectedContext && !supportsProtectedContent())) {
        return;
    }

    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([useProtectedContext, this](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::useProtectedContext");
            instance.useProtectedContext(useProtectedContext);
            if (instance.isProtected() != useProtectedContext) {
                ALOGE("Failed to switch RenderEngine context.");
                // reset the cached mIsProtected value to a good state, but this does not
                // prevent other callers of this method and isProtected from reading the
                // invalid cached value.
                mIsProtected = instance.isProtected();
            }
        });
        mIsProtected = useProtectedContext;
    }
    mCondition.notify_one();
}

void RenderEngineThreaded::cleanupPostRender() {
    if (canSkipPostRenderCleanup()) {
        return;
    }

    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([=](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::cleanupPostRender");
            instance.cleanupPostRender();
        });
    }
    mCondition.notify_one();
}

bool RenderEngineThreaded::canSkipPostRenderCleanup() const {
    waitUntilInitialized();
    return mRenderEngine->canSkipPostRenderCleanup();
}

void RenderEngineThreaded::drawLayersInternal(
        const std::shared_ptr<std::promise<RenderEngineResult>>&& resultPromise,
        const DisplaySettings& display, const std::vector<LayerSettings>& layers,
        const std::shared_ptr<ExternalTexture>& buffer, const bool useFramebufferCache,
        base::unique_fd&& bufferFence) {
    resultPromise->set_value({NO_ERROR, base::unique_fd()});
    return;
}

std::future<RenderEngineResult> RenderEngineThreaded::drawLayers(
        const DisplaySettings& display, const std::vector<LayerSettings>& layers,
        const std::shared_ptr<ExternalTexture>& buffer, const bool useFramebufferCache,
        base::unique_fd&& bufferFence) {
    ATRACE_CALL();
    const auto resultPromise = std::make_shared<std::promise<RenderEngineResult>>();
    std::future<RenderEngineResult> resultFuture = resultPromise->get_future();
    int fd = bufferFence.release();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([resultPromise, display, layers, buffer, useFramebufferCache,
                             fd](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::drawLayers");
            instance.drawLayersInternal(std::move(resultPromise), display, layers, buffer,
                                        useFramebufferCache, base::unique_fd(fd));
        });
    }
    mCondition.notify_one();
    return resultFuture;
}

void RenderEngineThreaded::cleanFramebufferCache() {
    ATRACE_CALL();
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::cleanFramebufferCache");
            instance.cleanFramebufferCache();
        });
    }
    mCondition.notify_one();
}

int RenderEngineThreaded::getContextPriority() {
    std::promise<int> resultPromise;
    std::future<int> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::getContextPriority");
            int priority = instance.getContextPriority();
            resultPromise.set_value(priority);
        });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

bool RenderEngineThreaded::supportsBackgroundBlur() {
    waitUntilInitialized();
    return mRenderEngine->supportsBackgroundBlur();
}

void RenderEngineThreaded::onActiveDisplaySizeChanged(ui::Size size) {
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([size](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::onActiveDisplaySizeChanged");
            instance.onActiveDisplaySizeChanged(size);
        });
    }
    mCondition.notify_one();
}

std::optional<pid_t> RenderEngineThreaded::getRenderEngineTid() const {
    std::promise<pid_t> tidPromise;
    std::future<pid_t> tidFuture = tidPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&tidPromise](renderengine::RenderEngine& instance) {
            tidPromise.set_value(gettid());
        });
    }

    mCondition.notify_one();
    return std::make_optional(tidFuture.get());
}

void RenderEngineThreaded::setEnableTracing(bool tracingEnabled) {
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([tracingEnabled](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::setEnableTracing");
            instance.setEnableTracing(tracingEnabled);
        });
    }
    mCondition.notify_one();
}
} // namespace threaded
} // namespace renderengine
} // namespace android
