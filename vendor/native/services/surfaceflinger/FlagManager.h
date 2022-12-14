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

#include <cstdint>
#include <optional>
#include <string>

namespace android {
// Manages flags for SurfaceFlinger, including default values, system properties, and Mendel
// experiment configuration values.
class FlagManager {
public:
    FlagManager() = default;
    virtual ~FlagManager();
    void dump(std::string& result) const;

    int64_t demo_flag() const;

    bool use_adpf_cpu_hint() const;

    bool use_skia_tracing() const;

private:
    friend class FlagManagerTest;

    // Wrapper for mocking in test.
    virtual std::string getServerConfigurableFlag(const std::string& experimentFlagName) const;

    template <typename T>
    T getValue(const std::string& experimentFlagName, std::optional<T> systemPropertyOpt,
               T defaultValue) const;
};
} // namespace android
