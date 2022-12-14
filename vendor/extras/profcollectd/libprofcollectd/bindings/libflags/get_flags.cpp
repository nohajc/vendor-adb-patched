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

#include "../../../../../server_configurable_flags/libflags/include/server_configurable_flags/get_flags.h"
#include "get_flags.hpp"

const char* GetServerConfigurableFlag(const char* experiment_category_name,
                                      const char* experiment_flag_name,
                                      const char* default_value) {
    auto v = server_configurable_flags::GetServerConfigurableFlag(
        std::string(experiment_category_name),
        std::string(experiment_flag_name),
        std::string(default_value));
    return strdup(v.c_str());
}
