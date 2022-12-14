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

#include <ui/StaticDisplayInfo.h>

#include <cstdint>

#include <ui/FlattenableHelpers.h>

#define RETURN_IF_ERROR(op) \
    if (const status_t status = (op); status != OK) return status;

namespace android::ui {

size_t StaticDisplayInfo::getFlattenedSize() const {
    return FlattenableHelpers::getFlattenedSize(connectionType) +
            FlattenableHelpers::getFlattenedSize(density) +
            FlattenableHelpers::getFlattenedSize(secure) +
            FlattenableHelpers::getFlattenedSize(deviceProductInfo);
}

status_t StaticDisplayInfo::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, connectionType));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, density));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, secure));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, deviceProductInfo));
    return OK;
}

status_t StaticDisplayInfo::unflatten(void const* buffer, size_t size) {
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &connectionType));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &density));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &secure));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &deviceProductInfo));
    return OK;
}

} // namespace android::ui
