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

#include <ui/DeviceProductInfo.h>

#include <android-base/stringprintf.h>
#include <ui/FlattenableHelpers.h>
#include <utils/Log.h>

#define RETURN_IF_ERROR(op) \
    if (const status_t status = (op); status != OK) return status;

namespace android {

using base::StringAppendF;

size_t DeviceProductInfo::getFlattenedSize() const {
    return FlattenableHelpers::getFlattenedSize(name) +
            FlattenableHelpers::getFlattenedSize(manufacturerPnpId) +
            FlattenableHelpers::getFlattenedSize(productId) +
            FlattenableHelpers::getFlattenedSize(manufactureOrModelDate) +
            FlattenableHelpers::getFlattenedSize(relativeAddress);
}

status_t DeviceProductInfo::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, name));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, manufacturerPnpId));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, productId));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, manufactureOrModelDate));
    RETURN_IF_ERROR(FlattenableHelpers::flatten(&buffer, &size, relativeAddress));
    return OK;
}

status_t DeviceProductInfo::unflatten(void const* buffer, size_t size) {
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &name));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &manufacturerPnpId));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &productId));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &manufactureOrModelDate));
    RETURN_IF_ERROR(FlattenableHelpers::unflatten(&buffer, &size, &relativeAddress));
    return OK;
}

void DeviceProductInfo::dump(std::string& result) const {
    StringAppendF(&result, "{name=\"%s\", ", name.c_str());
    StringAppendF(&result, "manufacturerPnpId=%s, ", manufacturerPnpId.data());
    StringAppendF(&result, "productId=%s, ", productId.c_str());

    if (const auto* model = std::get_if<ModelYear>(&manufactureOrModelDate)) {
        StringAppendF(&result, "modelYear=%u, ", model->year);
    } else if (const auto* manufactureWeekAndYear =
                       std::get_if<ManufactureWeekAndYear>(&manufactureOrModelDate)) {
        StringAppendF(&result, "manufactureWeek=%u, ", manufactureWeekAndYear->week);
        StringAppendF(&result, "manufactureYear=%d, ", manufactureWeekAndYear->year);
    } else if (const auto* manufactureYear =
                       std::get_if<ManufactureYear>(&manufactureOrModelDate)) {
        StringAppendF(&result, "manufactureYear=%d, ", manufactureYear->year);
    } else {
        ALOGE("Unknown alternative for variant DeviceProductInfo::ManufactureOrModelDate");
    }

    result.append("relativeAddress=[");
    for (size_t i = 0; i < relativeAddress.size(); i++) {
        if (i != 0) {
            result.append(", ");
        }
        StringAppendF(&result, "%u", relativeAddress[i]);
    }
    result.append("]}");
}

} // namespace android
