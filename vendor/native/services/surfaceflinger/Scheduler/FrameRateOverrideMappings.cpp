/*
 * Copyright 2022 The Android Open Source Project
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

#include "FrameRateOverrideMappings.h"

namespace android::scheduler {
using FrameRateOverride = DisplayEventReceiver::Event::FrameRateOverride;

std::optional<Fps> FrameRateOverrideMappings::getFrameRateOverrideForUid(
        uid_t uid, bool supportsFrameRateOverrideByContent) const {
    std::lock_guard lock(mFrameRateOverridesLock);

    {
        const auto iter = mFrameRateOverridesFromBackdoor.find(uid);
        if (iter != mFrameRateOverridesFromBackdoor.end()) {
            return iter->second;
        }
    }

    {
        const auto iter = mFrameRateOverridesFromGameManager.find(uid);
        if (iter != mFrameRateOverridesFromGameManager.end()) {
            return iter->second;
        }
    }

    if (!supportsFrameRateOverrideByContent) {
        return std::nullopt;
    }

    {
        const auto iter = mFrameRateOverridesByContent.find(uid);
        if (iter != mFrameRateOverridesByContent.end()) {
            return iter->second;
        }
    }

    return std::nullopt;
}

std::vector<FrameRateOverride> FrameRateOverrideMappings::getAllFrameRateOverrides(
        bool supportsFrameRateOverrideByContent) {
    std::lock_guard lock(mFrameRateOverridesLock);
    std::vector<FrameRateOverride> overrides;
    overrides.reserve(std::max({mFrameRateOverridesFromGameManager.size(),
                                mFrameRateOverridesFromBackdoor.size(),
                                mFrameRateOverridesByContent.size()}));

    for (const auto& [uid, frameRate] : mFrameRateOverridesFromBackdoor) {
        overrides.emplace_back(FrameRateOverride{uid, frameRate.getValue()});
    }
    for (const auto& [uid, frameRate] : mFrameRateOverridesFromGameManager) {
        if (std::find_if(overrides.begin(), overrides.end(),
                         [uid = uid](auto i) { return i.uid == uid; }) == overrides.end()) {
            overrides.emplace_back(FrameRateOverride{uid, frameRate.getValue()});
        }
    }

    if (!supportsFrameRateOverrideByContent) {
        return overrides;
    }

    for (const auto& [uid, frameRate] : mFrameRateOverridesByContent) {
        if (std::find_if(overrides.begin(), overrides.end(),
                         [uid = uid](auto i) { return i.uid == uid; }) == overrides.end()) {
            overrides.emplace_back(FrameRateOverride{uid, frameRate.getValue()});
        }
    }

    return overrides;
}

void FrameRateOverrideMappings::dump(std::string& result) const {
    using base::StringAppendF;

    std::lock_guard lock(mFrameRateOverridesLock);

    StringAppendF(&result, "Frame Rate Overrides (backdoor): {");
    for (const auto& [uid, frameRate] : mFrameRateOverridesFromBackdoor) {
        StringAppendF(&result, "[uid: %d frameRate: %s], ", uid, to_string(frameRate).c_str());
    }
    StringAppendF(&result, "}\n");

    StringAppendF(&result, "Frame Rate Overrides (GameManager): {");
    for (const auto& [uid, frameRate] : mFrameRateOverridesFromGameManager) {
        StringAppendF(&result, "[uid: %d frameRate: %s], ", uid, to_string(frameRate).c_str());
    }
    StringAppendF(&result, "}\n");

    StringAppendF(&result, "Frame Rate Overrides (setFrameRate): {");
    for (const auto& [uid, frameRate] : mFrameRateOverridesByContent) {
        StringAppendF(&result, "[uid: %d frameRate: %s], ", uid, to_string(frameRate).c_str());
    }
    StringAppendF(&result, "}\n");
}

bool FrameRateOverrideMappings::updateFrameRateOverridesByContent(
        const UidToFrameRateOverride& frameRateOverrides) {
    std::lock_guard lock(mFrameRateOverridesLock);
    if (!std::equal(mFrameRateOverridesByContent.begin(), mFrameRateOverridesByContent.end(),
                    frameRateOverrides.begin(), frameRateOverrides.end(),
                    [](const auto& lhs, const auto& rhs) {
                        return lhs.first == rhs.first && isApproxEqual(lhs.second, rhs.second);
                    })) {
        mFrameRateOverridesByContent = frameRateOverrides;
        return true;
    }
    return false;
}

void FrameRateOverrideMappings::setGameModeRefreshRateForUid(FrameRateOverride frameRateOverride) {
    std::lock_guard lock(mFrameRateOverridesLock);
    if (frameRateOverride.frameRateHz != 0.f) {
        mFrameRateOverridesFromGameManager[frameRateOverride.uid] =
                Fps::fromValue(frameRateOverride.frameRateHz);
    } else {
        mFrameRateOverridesFromGameManager.erase(frameRateOverride.uid);
    }
}

void FrameRateOverrideMappings::setPreferredRefreshRateForUid(FrameRateOverride frameRateOverride) {
    std::lock_guard lock(mFrameRateOverridesLock);
    if (frameRateOverride.frameRateHz != 0.f) {
        mFrameRateOverridesFromBackdoor[frameRateOverride.uid] =
                Fps::fromValue(frameRateOverride.frameRateHz);
    } else {
        mFrameRateOverridesFromBackdoor.erase(frameRateOverride.uid);
    }
}
} // namespace android::scheduler
