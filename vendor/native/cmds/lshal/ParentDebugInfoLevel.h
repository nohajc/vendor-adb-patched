/*
 * Copyright (C) 2020 The Android Open Source Project
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

namespace android {
namespace lshal {

// Describe verbosity when dumping debug information on a HAL service by
// referring to a parent HAL interface FQName (for example, when dumping debug information
// on foo@1.0::IFoo but the HAL implementation is foo@1.1::IFoo).
enum class ParentDebugInfoLevel {
    // Write nothing.
    NOTHING,
    // Write a short description that includes the FQName of the real implementation.
    FQNAME_ONLY,
    // Write full debug info.
    FULL,
};

} // namespace lshal
} // namespace android
