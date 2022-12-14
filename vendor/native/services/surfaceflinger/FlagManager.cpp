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

#include "FlagManager.h"

#include <SurfaceFlingerProperties.sysprop.h>
#include <android-base/parsebool.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <log/log.h>
#include <renderengine/RenderEngine.h>
#include <server_configurable_flags/get_flags.h>
#include <cinttypes>

namespace android {
static constexpr const char* kExperimentNamespace = "surface_flinger_native_boot";
static constexpr const int64_t kDemoFlag = -1;

FlagManager::~FlagManager() = default;

void FlagManager::dump(std::string& result) const {
    base::StringAppendF(&result, "FlagManager values: \n");
    base::StringAppendF(&result, "demo_flag: %" PRId64 "\n", demo_flag());
    base::StringAppendF(&result, "use_adpf_cpu_hint: %s\n", use_adpf_cpu_hint() ? "true" : "false");
    base::StringAppendF(&result, "use_skia_tracing: %s\n", use_skia_tracing() ? "true" : "false");
}

namespace {
template <typename T>
std::optional<T> doParse(const char* str);

template <>
[[maybe_unused]] std::optional<int32_t> doParse(const char* str) {
    int32_t ret;
    return base::ParseInt(str, &ret) ? std::make_optional(ret) : std::nullopt;
}

template <>
[[maybe_unused]] std::optional<int64_t> doParse(const char* str) {
    int64_t ret;
    return base::ParseInt(str, &ret) ? std::make_optional(ret) : std::nullopt;
}

template <>
[[maybe_unused]] std::optional<bool> doParse(const char* str) {
    base::ParseBoolResult parseResult = base::ParseBool(str);
    switch (parseResult) {
        case base::ParseBoolResult::kTrue:
            return std::make_optional(true);
        case base::ParseBoolResult::kFalse:
            return std::make_optional(false);
        case base::ParseBoolResult::kError:
            return std::nullopt;
    }
}
} // namespace

std::string FlagManager::getServerConfigurableFlag(const std::string& experimentFlagName) const {
    return server_configurable_flags::GetServerConfigurableFlag(kExperimentNamespace,
                                                                experimentFlagName, "");
}

template int32_t FlagManager::getValue<int32_t>(const std::string&, std::optional<int32_t>,
                                                int32_t) const;
template int64_t FlagManager::getValue<int64_t>(const std::string&, std::optional<int64_t>,
                                                int64_t) const;
template bool FlagManager::getValue<bool>(const std::string&, std::optional<bool>, bool) const;
template <typename T>
T FlagManager::getValue(const std::string& experimentFlagName, std::optional<T> systemPropertyOpt,
                        T defaultValue) const {
    // System property takes precedence over the experiment config server value.
    if (systemPropertyOpt.has_value()) {
        return *systemPropertyOpt;
    }
    std::string str = getServerConfigurableFlag(experimentFlagName);
    return str.empty() ? defaultValue : doParse<T>(str.c_str()).value_or(defaultValue);
}

int64_t FlagManager::demo_flag() const {
    std::optional<int64_t> sysPropVal = std::nullopt;
    return getValue("DemoFeature__demo_flag", sysPropVal, kDemoFlag);
}

bool FlagManager::use_adpf_cpu_hint() const {
    std::optional<bool> sysPropVal =
            doParse<bool>(base::GetProperty("debug.sf.enable_adpf_cpu_hint", "").c_str());
    return getValue("AdpfFeature__adpf_cpu_hint", sysPropVal, false);
}

bool FlagManager::use_skia_tracing() const {
    std::optional<bool> sysPropVal =
            doParse<bool>(base::GetProperty(PROPERTY_SKIA_ATRACE_ENABLED, "").c_str());
    return getValue("SkiaTracingFeature__use_skia_tracing", sysPropVal, false);
}

} // namespace android
