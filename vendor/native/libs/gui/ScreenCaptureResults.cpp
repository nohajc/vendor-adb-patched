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

#include <gui/ScreenCaptureResults.h>

#include <private/gui/ParcelUtils.h>

namespace android::gui {

status_t ScreenCaptureResults::writeToParcel(android::Parcel* parcel) const {
    if (buffer != nullptr) {
        SAFE_PARCEL(parcel->writeBool, true);
        SAFE_PARCEL(parcel->write, *buffer);
    } else {
        SAFE_PARCEL(parcel->writeBool, false);
    }

    if (fence != Fence::NO_FENCE) {
        SAFE_PARCEL(parcel->writeBool, true);
        SAFE_PARCEL(parcel->write, *fence);
    } else {
        SAFE_PARCEL(parcel->writeBool, false);
    }

    SAFE_PARCEL(parcel->writeBool, capturedSecureLayers);
    SAFE_PARCEL(parcel->writeUint32, static_cast<uint32_t>(capturedDataspace));
    SAFE_PARCEL(parcel->writeInt32, result);
    return NO_ERROR;
}

status_t ScreenCaptureResults::readFromParcel(const android::Parcel* parcel) {
    bool hasGraphicBuffer;
    SAFE_PARCEL(parcel->readBool, &hasGraphicBuffer);
    if (hasGraphicBuffer) {
        buffer = new GraphicBuffer();
        SAFE_PARCEL(parcel->read, *buffer);
    }

    bool hasFence;
    SAFE_PARCEL(parcel->readBool, &hasFence);
    if (hasFence) {
        fence = new Fence();
        SAFE_PARCEL(parcel->read, *fence);
    }

    SAFE_PARCEL(parcel->readBool, &capturedSecureLayers);
    uint32_t dataspace = 0;
    SAFE_PARCEL(parcel->readUint32, &dataspace);
    capturedDataspace = static_cast<ui::Dataspace>(dataspace);
    SAFE_PARCEL(parcel->readInt32, &result);
    return NO_ERROR;
}

} // namespace android::gui
