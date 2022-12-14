/*
 * Copyright (C) 2010 The Android Open Source Project
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

#define LOG_TAG "Surface"

#include <android/binder_libbinder.h>
#include <android/binder_parcel.h>
#include <android/native_window.h>
#include <binder/Parcel.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/Surface.h>
#include <gui/view/Surface.h>
#include <system/window.h>
#include <utils/Log.h>

namespace android {
namespace view {

// Since this is a parcelable utility and we want to keep the wire format stable, only build this
// when building the system libgui to detect any issues loading the wrong libgui from
// libnativewindow

#if (!defined(__ANDROID_APEX__) && !defined(__ANDROID_VNDK__))

extern "C" status_t android_view_Surface_writeToParcel(ANativeWindow* _Nonnull window,
                                                       Parcel* _Nonnull parcel) {
    int value;
    int err = (*window->query)(window, NATIVE_WINDOW_CONCRETE_TYPE, &value);
    if (err != OK || value != NATIVE_WINDOW_SURFACE) {
        ALOGE("Error: ANativeWindow is not backed by Surface");
        return STATUS_BAD_VALUE;
    }
    // Use a android::view::Surface to parcelize the window
    android::view::Surface shimSurface;
    shimSurface.graphicBufferProducer = android::Surface::getIGraphicBufferProducer(window);
    shimSurface.surfaceControlHandle = android::Surface::getSurfaceControlHandle(window);
    return shimSurface.writeToParcel(parcel);
}

extern "C" status_t android_view_Surface_readFromParcel(
        const Parcel* _Nonnull parcel, ANativeWindow* _Nullable* _Nonnull outWindow) {
    // Use a android::view::Surface to unparcel the window
    android::view::Surface shimSurface;
    status_t ret = shimSurface.readFromParcel(parcel);
    if (ret != OK) {
        ALOGE("%s: Error: Failed to create android::view::Surface from AParcel", __FUNCTION__);
        return STATUS_BAD_VALUE;
    }
    auto surface = sp<android::Surface>::make(shimSurface.graphicBufferProducer, false,
                                              shimSurface.surfaceControlHandle);
    ANativeWindow* anw = surface.get();
    ANativeWindow_acquire(anw);
    *outWindow = anw;
    return STATUS_OK;
}

#endif

status_t Surface::writeToParcel(Parcel* parcel) const {
    return writeToParcel(parcel, false);
}

status_t Surface::writeToParcel(Parcel* parcel, bool nameAlreadyWritten) const {
    if (parcel == nullptr) return BAD_VALUE;

    status_t res = OK;

    if (!nameAlreadyWritten) {
        res = parcel->writeString16(name);
        if (res != OK) return res;

        /* isSingleBuffered defaults to no */
        res = parcel->writeInt32(0);
        if (res != OK) return res;
    }

    res = IGraphicBufferProducer::exportToParcel(graphicBufferProducer, parcel);
    if (res != OK) return res;
    return parcel->writeStrongBinder(surfaceControlHandle);
}

status_t Surface::readFromParcel(const Parcel* parcel) {
    return readFromParcel(parcel, false);
}

status_t Surface::readFromParcel(const Parcel* parcel, bool nameAlreadyRead) {
    if (parcel == nullptr) return BAD_VALUE;

    status_t res = OK;
    if (!nameAlreadyRead) {
        name = readMaybeEmptyString16(parcel);
        // Discard this for now
        int isSingleBuffered;
        res = parcel->readInt32(&isSingleBuffered);
        if (res != OK) {
            ALOGE("Can't read isSingleBuffered");
            return res;
        }
    }

    graphicBufferProducer = IGraphicBufferProducer::createFromParcel(parcel);
    surfaceControlHandle = parcel->readStrongBinder();
    return OK;
}

String16 Surface::readMaybeEmptyString16(const Parcel* parcel) {
    std::optional<String16> str;
    parcel->readString16(&str);
    return str.value_or(String16());
}

} // namespace view
} // namespace android
