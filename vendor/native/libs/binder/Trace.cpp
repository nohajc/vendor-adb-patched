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

#include <binder/Trace.h>
#include <cutils/trace.h>

namespace android {
namespace binder {

void atrace_begin(uint64_t tag, const char* name) {
    ::atrace_begin(tag, name);
}

void atrace_end(uint64_t tag) {
    ::atrace_end(tag);
}

} // namespace binder
} // namespace android
