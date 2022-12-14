/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <stdint.h>
#include <sys/types.h>

#include <android/gui/ISurfaceComposer.h>

#include <utils/Singleton.h>
#include <utils/StrongPointer.h>

namespace android {

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

// This holds our connection to the composer service (i.e. SurfaceFlinger).
// If the remote side goes away, we will re-establish the connection.
// Users of this class should not retain the value from
// getComposerService() for an extended period.
//
// (TODO: b/219785927, It's not clear that using Singleton is useful here anymore.)
class ComposerServiceAIDL : public Singleton<ComposerServiceAIDL> {
    sp<gui::ISurfaceComposer> mComposerService;
    sp<IBinder::DeathRecipient> mDeathObserver;
    mutable std::mutex mMutex;

    ComposerServiceAIDL();
    bool connectLocked();
    void composerServiceDied();
    friend class Singleton<ComposerServiceAIDL>;

public:
    // Get a connection to the Composer Service.  This will block until
    // a connection is established. Returns null if permission is denied.
    static sp<gui::ISurfaceComposer> getComposerService();

    // the following two methods are moved from ISurfaceComposer.h
    // TODO(b/74619554): Remove this stopgap once the framework is display-agnostic.
    std::optional<PhysicalDisplayId> getInternalDisplayId() const {
        std::vector<int64_t> displayIds;
        binder::Status status = mComposerService->getPhysicalDisplayIds(&displayIds);
        return (!status.isOk() || displayIds.empty())
                ? std::nullopt
                : DisplayId::fromValue<PhysicalDisplayId>(
                          static_cast<uint64_t>(displayIds.front()));
    }

    // TODO(b/74619554): Remove this stopgap once the framework is display-agnostic.
    sp<IBinder> getInternalDisplayToken() const {
        const auto displayId = getInternalDisplayId();
        if (!displayId) return nullptr;
        sp<IBinder> display;
        binder::Status status =
                mComposerService->getPhysicalDisplayToken(static_cast<int64_t>(displayId->value),
                                                          &display);
        return status.isOk() ? display : nullptr;
    }
};

// ---------------------------------------------------------------------------
}; // namespace android
