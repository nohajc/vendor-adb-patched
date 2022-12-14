/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <stdint.h>
#include <sys/types.h>

#include <binder/IBinder.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <ui/GraphicTypes.h>
#include <ui/PixelFormat.h>

namespace android::gui {

struct CaptureArgs : public Parcelable {
    const static int32_t UNSET_UID = -1;
    virtual ~CaptureArgs() = default;

    ui::PixelFormat pixelFormat{ui::PixelFormat::RGBA_8888};
    Rect sourceCrop;
    float frameScaleX{1};
    float frameScaleY{1};
    bool captureSecureLayers{false};
    int32_t uid{UNSET_UID};
    // Force capture to be in a color space. If the value is ui::Dataspace::UNKNOWN, the captured
    // result will be in the display's colorspace.
    // The display may use non-RGB dataspace (ex. displayP3) that could cause pixel data could be
    // different from SRGB (byte per color), and failed when checking colors in tests.
    // NOTE: In normal cases, we want the screen to be captured in display's colorspace.
    ui::Dataspace dataspace = ui::Dataspace::UNKNOWN;

    // The receiver of the capture can handle protected buffer. A protected buffer has
    // GRALLOC_USAGE_PROTECTED usage bit and must not be accessed unprotected behaviour.
    // Any read/write access from unprotected context will result in undefined behaviour.
    // Protected contents are typically DRM contents. This has no direct implication to the
    // secure property of the surface, which is specified by the application explicitly to avoid
    // the contents being accessed/captured by screenshot or unsecure display.
    bool allowProtected = false;

    bool grayscale = false;

    virtual status_t writeToParcel(Parcel* output) const;
    virtual status_t readFromParcel(const Parcel* input);
};

struct DisplayCaptureArgs : CaptureArgs {
    sp<IBinder> displayToken;
    uint32_t width{0};
    uint32_t height{0};
    bool useIdentityTransform{false};

    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;
};

}; // namespace android::gui
