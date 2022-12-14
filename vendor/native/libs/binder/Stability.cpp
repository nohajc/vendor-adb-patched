/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define LOG_TAG "Stability"

#include <binder/Stability.h>

#include <binder/BpBinder.h>
#include <binder/Binder.h>

namespace android {
namespace internal {

void Stability::forceDowngradeToStability(const sp<IBinder>& binder, Level level) {
    // Downgrading a remote binder would require also copying the version from
    // the binder sent here. In practice though, we don't need to downgrade the
    // stability of a remote binder, since this would as an effect only restrict
    // what we can do to it.
    LOG_ALWAYS_FATAL_IF(!binder || !binder->localBinder(), "Can only downgrade local binder");

    status_t result = setRepr(binder.get(), level, REPR_LOG | REPR_ALLOW_DOWNGRADE);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

void Stability::forceDowngradeToLocalStability(const sp<IBinder>& binder) {
    forceDowngradeToStability(binder, getLocalLevel());
}

void Stability::forceDowngradeToSystemStability(const sp<IBinder>& binder) {
    forceDowngradeToStability(binder, Level::SYSTEM);
}

void Stability::forceDowngradeToVendorStability(const sp<IBinder>& binder) {
    forceDowngradeToStability(binder, Level::VENDOR);
}

void Stability::markCompilationUnit(IBinder* binder) {
    status_t result = setRepr(binder, getLocalLevel(), REPR_LOG);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

void Stability::markVintf(IBinder* binder) {
    status_t result = setRepr(binder, Level::VINTF, REPR_LOG);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

std::string Stability::debugToString(const sp<IBinder>& binder) {
    return levelString(getRepr(binder.get()));
}

void Stability::markVndk(IBinder* binder) {
    status_t result = setRepr(binder, Level::VENDOR, REPR_LOG);
    LOG_ALWAYS_FATAL_IF(result != OK, "Should only mark known object.");
}

bool Stability::requiresVintfDeclaration(const sp<IBinder>& binder) {
    return check(getRepr(binder.get()), Level::VINTF);
}

void Stability::tryMarkCompilationUnit(IBinder* binder) {
    (void)setRepr(binder, getLocalLevel(), REPR_NONE);
}

Stability::Level Stability::getLocalLevel() {
#ifdef __ANDROID_APEX__
#error APEX can't use libbinder (must use libbinder_ndk)
#endif

#ifdef __ANDROID_VNDK__
    return Level::VENDOR;
#else
    // TODO(b/139325195): split up stability levels for system/APEX.
    return Level::SYSTEM;
#endif
}

status_t Stability::setRepr(IBinder* binder, int32_t setting, uint32_t flags) {
    bool log = flags & REPR_LOG;
    bool allowDowngrade = flags & REPR_ALLOW_DOWNGRADE;

    int16_t current = getRepr(binder);

    // null binder is always written w/ 'UNDECLARED' stability
    if (binder == nullptr) {
        if (setting == UNDECLARED) {
            return OK;
        } else {
            if (log) {
                ALOGE("Null binder written with stability %s.", levelString(setting).c_str());
            }
            return BAD_TYPE;
        }
    }

    if (!isDeclaredLevel(setting)) {
        if (log) {
            ALOGE("Can only set known stability, not %d.", setting);
        }
        return BAD_TYPE;
    }
    Level levelSetting = static_cast<Level>(setting);

    if (current == setting) return OK;

    bool hasAlreadyBeenSet = current != Level::UNDECLARED;
    bool isAllowedDowngrade = allowDowngrade && check(current, levelSetting);
    if (hasAlreadyBeenSet && !isAllowedDowngrade) {
        if (log) {
            ALOGE("Interface being set with %s but it is already marked as %s",
                  levelString(setting).c_str(), levelString(current).c_str());
        }
        return BAD_TYPE;
    }

    if (isAllowedDowngrade) {
        ALOGI("Interface set with %s downgraded to %s stability", levelString(current).c_str(),
              levelString(setting).c_str());
    }

    BBinder* local = binder->localBinder();
    if (local != nullptr) {
        local->mStability = setting;
    } else {
        binder->remoteBinder()->mStability = setting;
    }

    return OK;
}

int16_t Stability::getRepr(IBinder* binder) {
    if (binder == nullptr) {
        return Level::UNDECLARED;
    }

    BBinder* local = binder->localBinder();
    if (local != nullptr) {
        return local->mStability;
    }

    return binder->remoteBinder()->mStability;
}

bool Stability::check(int16_t provided, Level required) {
    bool stable = (provided & required) == required;

    if (provided != UNDECLARED && !isDeclaredLevel(provided)) {
        ALOGE("Unknown stability when checking interface stability %d.", provided);

        stable = false;
    }

    return stable;
}

bool Stability::isDeclaredLevel(int32_t stability) {
    return stability == VENDOR || stability == SYSTEM || stability == VINTF;
}

std::string Stability::levelString(int32_t level) {
    switch (level) {
        case Level::UNDECLARED: return "undeclared stability";
        case Level::VENDOR: return "vendor stability";
        case Level::SYSTEM: return "system stability";
        case Level::VINTF: return "vintf stability";
    }
    return "unknown stability " + std::to_string(level);
}

}  // namespace internal
}  // namespace stability
