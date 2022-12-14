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
#define LOG_TAG "installd"

#include "execv_helper.h"

#include <stdlib.h>
#include <unistd.h>

#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>

namespace android {
namespace installd {

// Store a placeholder for the binary name.
ExecVHelper::ExecVHelper() : args_(1u, std::string()) {}

ExecVHelper::~ExecVHelper() {}

void ExecVHelper::PrepareArgs(const std::string& bin) {
    CHECK(!args_.empty());
    CHECK(args_[0].empty());
    args_[0] = bin;
    // Write char* into array.
    for (const std::string& arg : args_) {
        argv_.push_back(arg.c_str());
    }
    argv_.push_back(nullptr);  // Add null terminator.
}

void ExecVHelper::Exec(int exit_code) {
    execv(argv_[0], (char * const *)&argv_[0]);
    PLOG(ERROR) << "execv(" << argv_[0] << ") failed";
    exit(exit_code);
}

void ExecVHelper::AddArg(const std::string& arg) {
    if (!arg.empty()) {
        args_.push_back(arg);
    }
}

void ExecVHelper::AddRuntimeArg(const std::string& arg) {
    if (!arg.empty()) {
        args_.push_back("--runtime-arg");
        args_.push_back(arg);
    }
}

}  // namespace installd
}  // namespace android
