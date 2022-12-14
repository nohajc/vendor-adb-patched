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

#include <ui/DisplayId.h>

#include <limits>
#include <optional>
#include <random>
#include <unordered_set>

#include <log/log.h>

namespace android {

// Generates pseudo-random IDs of type GpuVirtualDisplayId or HalVirtualDisplayId.
template <typename Id>
class DisplayIdGenerator {
public:
    explicit DisplayIdGenerator(size_t maxIdsCount = std::numeric_limits<size_t>::max())
          : mMaxIdsCount(maxIdsCount) {}

    bool inUse() const { return !mUsedIds.empty(); }

    std::optional<Id> generateId() {
        if (mUsedIds.size() >= mMaxIdsCount) {
            return std::nullopt;
        }

        constexpr int kMaxAttempts = 1000;

        for (int attempts = 0; attempts < kMaxAttempts; attempts++) {
            const Id id{mDistribution(mGenerator)};
            if (mUsedIds.count(id) == 0) {
                mUsedIds.insert(id);
                return id;
            }
        }

        LOG_ALWAYS_FATAL("Couldn't generate ID after %d attempts", kMaxAttempts);
    }

    void releaseId(Id id) { mUsedIds.erase(id); }

private:
    const size_t mMaxIdsCount;

    std::unordered_set<Id> mUsedIds;

    // Pseudo-random with random seed, in contrast to physical display IDs, which are stable
    // across reboots. The only ISurfaceComposer exposure for these IDs is a restricted API
    // for screencap, so there is little benefit in making them unpredictable.
    std::default_random_engine mGenerator{std::random_device()()};
    std::uniform_int_distribution<typename Id::BaseId> mDistribution;
};

} // namespace android
