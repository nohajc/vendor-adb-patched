/*
 * Copyright 2021 The Android Open Source Project
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

#include <ui/DynamicDisplayInfo.h>

#include <cstdint>

#include <ui/FlattenableHelpers.h>

#define RETURN_IF_ERROR(op) \
    if (const status_t status = (op); status != OK) return status;

namespace android::ui {

std::optional<ui::DisplayMode> DynamicDisplayInfo::getActiveDisplayMode() const {
    for (const auto& currMode : supportedDisplayModes) {
        if (currMode.id == activeDisplayModeId) {
            return currMode;
        }
    }
    return {};
}

size_t DynamicDisplayInfo::getFlattenedSize() const {
    return FlattenableHelpers::getFlattenedSize(supportedDisplayModes) +
            FlattenableHelpers::getFlattenedSize(activeDisplayModeId) +
            FlattenableHelpers::getFlattenedSize(supportedColorModes) +
            FlattenableHelpers::getFlattenedSize(activeColorMode) +
            FlattenableHelpers::getFlattenedSize(hdrCapabilities) +
            FlattenableHelpers::getFlattenedSize(autoLowLatencyModeSupported) +
            FlattenableHelpers::getFlattenedSize(gameContentTypeSupported);
}

status_t DynamicDisplayInfo::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, supportedDisplayModes));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, activeDisplayModeId));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, supportedColorModes));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, activeColorMode));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, hdrCapabilities));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, autoLowLatencyModeSupported));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, gameContentTypeSupported));
    return OK;
}

status_t DynamicDisplayInfo::unflatten(const void* buffer, size_t size) {
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &supportedDisplayModes));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &activeDisplayModeId));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &supportedColorModes));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &activeColorMode));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &hdrCapabilities));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &autoLowLatencyModeSupported));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &gameContentTypeSupported));
    return OK;
}

} // namespace android::ui
