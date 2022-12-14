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

#include <ui/DisplayMode.h>

#include <cstdint>

#include <ui/FlattenableHelpers.h>

#define RETURN_IF_ERROR(op) \
    if (const status_t status = (op); status != OK) return status;

namespace android::ui {

size_t DisplayMode::getFlattenedSize() const {
    return FlattenableHelpers::getFlattenedSize(id) +
            FlattenableHelpers::getFlattenedSize(resolution) +
            FlattenableHelpers::getFlattenedSize(xDpi) +
            FlattenableHelpers::getFlattenedSize(yDpi) +
            FlattenableHelpers::getFlattenedSize(refreshRate) +
            FlattenableHelpers::getFlattenedSize(appVsyncOffset) +
            FlattenableHelpers::getFlattenedSize(sfVsyncOffset) +
            FlattenableHelpers::getFlattenedSize(presentationDeadline) +
            FlattenableHelpers::getFlattenedSize(group);
}

status_t DisplayMode::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, id));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, resolution));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, xDpi));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, yDpi));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, refreshRate));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, appVsyncOffset));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, sfVsyncOffset));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, presentationDeadline));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, group));
    return OK;
}

status_t DisplayMode::unflatten(const void* buffer, size_t size) {
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &id));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &resolution));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &xDpi));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &yDpi));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &refreshRate));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &appVsyncOffset));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &sfVsyncOffset));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &presentationDeadline));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &group));
    return OK;
}

} // namespace android::ui
