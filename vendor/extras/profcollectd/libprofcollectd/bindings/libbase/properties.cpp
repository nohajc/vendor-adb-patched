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

#include "../../../../../libbase/include/android-base/properties.h"
#include "properties.hpp"

rust::String GetProperty(rust::Str key, rust::Str default_value) {
  return android::base::GetProperty(std::string(key), std::string(default_value));
}

void SetProperty(rust::Str key, rust::Str value) {
  android::base::SetProperty(std::string(key), std::string(value));
}
