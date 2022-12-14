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

#pragma once

#include <GrAHardwareBufferUtils.h>
#include <GrDirectContext.h>
#include <SkImage.h>
#include <SkSurface.h>
#include <sys/types.h>
#include <ui/GraphicTypes.h>

#include "android-base/macros.h"

#include <mutex>
#include <vector>

namespace android {
namespace renderengine {
namespace skia {

/**
 * AutoBackendTexture manages GPU image lifetime. It is a ref-counted object
 * that keeps GPU resources alive until the last SkImage or SkSurface object using them is
 * destroyed.
 */
class AutoBackendTexture {
public:
    // Manager class that is responsible for the immediate or deferred cleanup
    // of AutoBackendTextures.  Clients of AutoBackendTexture are responsible for
    // ensuring that access to this class is thread safe.  Clients also control when
    // the resources are reclaimed by setting the manager into deferred mode.
    class CleanupManager {
    public:
        CleanupManager() = default;
        void add(AutoBackendTexture* abt) {
            if (mDeferCleanup) {
                mCleanupList.push_back(abt);
            } else {
                delete abt;
            }
        }

        void setDeferredStatus(bool enabled) { mDeferCleanup = enabled; }

        bool isEmpty() const { return mCleanupList.empty(); }

        // If any AutoBackedTextures were added while in deferred mode this method
        // will ensure they are deleted before returning.  It must only be called
        // on the thread where the GPU context that created the AutoBackedTexture
        // is active.
        void cleanup() {
            for (auto abt : mCleanupList) {
                delete abt;
            }
            mCleanupList.clear();
        }

    private:
        DISALLOW_COPY_AND_ASSIGN(CleanupManager);
        bool mDeferCleanup = false;
        std::vector<AutoBackendTexture*> mCleanupList;
    };

    // Local reference that supports RAII-style management of an AutoBackendTexture
    // AutoBackendTexture by itself can't be managed in a similar fashion because
    // of shared ownership with Skia objects, so we wrap it here instead.
    class LocalRef {
    public:
        LocalRef(GrDirectContext* context, AHardwareBuffer* buffer, bool isOutputBuffer,
                 CleanupManager& cleanupMgr) {
            mTexture = new AutoBackendTexture(context, buffer, isOutputBuffer, cleanupMgr);
            mTexture->ref();
        }

        ~LocalRef() {
            if (mTexture != nullptr) {
                mTexture->unref(true);
            }
        }

        // Makes a new SkImage from the texture content.
        // As SkImages are immutable but buffer content is not, we create
        // a new SkImage every time.
        sk_sp<SkImage> makeImage(ui::Dataspace dataspace, SkAlphaType alphaType,
                                 GrDirectContext* context) {
            return mTexture->makeImage(dataspace, alphaType, context);
        }

        // Makes a new SkSurface from the texture content, if needed.
        sk_sp<SkSurface> getOrCreateSurface(ui::Dataspace dataspace, GrDirectContext* context) {
            return mTexture->getOrCreateSurface(dataspace, context);
        }

        SkColorType colorType() const { return mTexture->mColorType; }

        DISALLOW_COPY_AND_ASSIGN(LocalRef);

    private:
        AutoBackendTexture* mTexture = nullptr;
    };

private:
    // Creates a GrBackendTexture whose contents come from the provided buffer.
    AutoBackendTexture(GrDirectContext* context, AHardwareBuffer* buffer, bool isOutputBuffer,
                       CleanupManager& cleanupMgr);

    // The only way to invoke dtor is with unref, when mUsageCount is 0.
    ~AutoBackendTexture();

    void ref() { mUsageCount++; }

    // releaseLocalResources is true if the underlying SkImage and SkSurface
    // should be deleted from local tracking.
    void unref(bool releaseLocalResources);

    // Makes a new SkImage from the texture content.
    // As SkImages are immutable but buffer content is not, we create
    // a new SkImage every time.
    sk_sp<SkImage> makeImage(ui::Dataspace dataspace, SkAlphaType alphaType,
                             GrDirectContext* context);

    // Makes a new SkSurface from the texture content, if needed.
    sk_sp<SkSurface> getOrCreateSurface(ui::Dataspace dataspace, GrDirectContext* context);

    GrBackendTexture mBackendTexture;
    GrAHardwareBufferUtils::DeleteImageProc mDeleteProc;
    GrAHardwareBufferUtils::UpdateImageProc mUpdateProc;
    GrAHardwareBufferUtils::TexImageCtx mImageCtx;

    CleanupManager& mCleanupMgr;

    static void releaseSurfaceProc(SkSurface::ReleaseContext releaseContext);
    static void releaseImageProc(SkImage::ReleaseContext releaseContext);

    int mUsageCount = 0;

    const bool mIsOutputBuffer;
    sk_sp<SkImage> mImage = nullptr;
    sk_sp<SkSurface> mSurface = nullptr;
    ui::Dataspace mDataspace = ui::Dataspace::UNKNOWN;
    SkColorType mColorType = kUnknown_SkColorType;
};

} // namespace skia
} // namespace renderengine
} // namespace android
