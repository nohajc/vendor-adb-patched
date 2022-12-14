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

#pragma once

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <gui/constants.h>
#include <ui/Transform.h>

namespace android::gui {

/*
 * Describes information about a display that can have windows in it.
 *
 * This should only be used by InputFlinger to support raw coordinates in logical display space.
 */
struct DisplayInfo : public Parcelable {
    int32_t displayId = ADISPLAY_ID_NONE;

    // Logical display dimensions.
    int32_t logicalWidth = 0;
    int32_t logicalHeight = 0;

    // The display transform. This takes display coordinates to logical display coordinates.
    ui::Transform transform;

    status_t writeToParcel(android::Parcel*) const override;

    status_t readFromParcel(const android::Parcel*) override;
};

} // namespace android::gui