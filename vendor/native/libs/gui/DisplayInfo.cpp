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

#define LOG_TAG "DisplayInfo"

#include <binder/Parcel.h>
#include <gui/DisplayInfo.h>
#include <private/gui/ParcelUtils.h>

#include <log/log.h>

namespace android::gui {

// --- DisplayInfo ---

status_t DisplayInfo::readFromParcel(const android::Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    float dsdx, dtdx, tx, dtdy, dsdy, ty;
    SAFE_PARCEL(parcel->readInt32, &displayId);
    SAFE_PARCEL(parcel->readInt32, &logicalWidth);
    SAFE_PARCEL(parcel->readInt32, &logicalHeight);
    SAFE_PARCEL(parcel->readFloat, &dsdx);
    SAFE_PARCEL(parcel->readFloat, &dtdx);
    SAFE_PARCEL(parcel->readFloat, &tx);
    SAFE_PARCEL(parcel->readFloat, &dtdy);
    SAFE_PARCEL(parcel->readFloat, &dsdy);
    SAFE_PARCEL(parcel->readFloat, &ty);

    transform.set({dsdx, dtdx, tx, dtdy, dsdy, ty, 0, 0, 1});

    return OK;
}

status_t DisplayInfo::writeToParcel(android::Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    SAFE_PARCEL(parcel->writeInt32, displayId);
    SAFE_PARCEL(parcel->writeInt32, logicalWidth);
    SAFE_PARCEL(parcel->writeInt32, logicalHeight);
    SAFE_PARCEL(parcel->writeFloat, transform.dsdx());
    SAFE_PARCEL(parcel->writeFloat, transform.dtdx());
    SAFE_PARCEL(parcel->writeFloat, transform.tx());
    SAFE_PARCEL(parcel->writeFloat, transform.dtdy());
    SAFE_PARCEL(parcel->writeFloat, transform.dsdy());
    SAFE_PARCEL(parcel->writeFloat, transform.ty());

    return OK;
}

} // namespace android::gui
