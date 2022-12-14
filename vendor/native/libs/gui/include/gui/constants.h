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

#pragma once

#include <stdint.h>

namespace android {

/**
 * Invalid value for display size. Used when display size isn't available.
 */
constexpr int32_t INVALID_DISPLAY_SIZE = 0;

enum {
    /* Used when an event is not associated with any display.
     * Typically used for non-pointer events. */
    ADISPLAY_ID_NONE = -1,

    /* The default display id. */
    ADISPLAY_ID_DEFAULT = 0,
};

} // namespace android