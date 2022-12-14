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

#include "unique_file.h"

#include <string>

#include <unistd.h>

#include <android-base/logging.h>

namespace android {
namespace installd {

UniqueFile::UniqueFile() : UniqueFile(-1, "") {}

UniqueFile::UniqueFile(int value, std::string path) : UniqueFile(value, path, nullptr) {}

UniqueFile::UniqueFile(int value, std::string path, CleanUpFunction cleanup)
        : value_(value), path_(path), cleanup_(cleanup), do_cleanup_(true), auto_close_(true) {}

UniqueFile::UniqueFile(UniqueFile&& other) {
    *this = std::move(other);
}

UniqueFile::~UniqueFile() {
    reset();
}

UniqueFile& UniqueFile::operator=(UniqueFile&& other) {
    value_ = other.value_;
    path_ = other.path_;
    cleanup_ = other.cleanup_;
    do_cleanup_ = other.do_cleanup_;
    auto_close_ = other.auto_close_;
    other.release();
    return *this;
}

void UniqueFile::reset() {
    reset(-1, "");
}

void UniqueFile::reset(int new_value, std::string path, CleanUpFunction new_cleanup) {
    if (auto_close_ && value_ >= 0) {
        if (close(value_) < 0) {
            PLOG(ERROR) << "Failed to close fd " << value_ << ", with path " << path;
        }
    }
    if (do_cleanup_ && cleanup_ != nullptr) {
        cleanup_(path_);
    }

    value_ = new_value;
    path_ = path;
    cleanup_ = new_cleanup;
}

void UniqueFile::release() {
    value_ = -1;
    path_ = "";
    do_cleanup_ = false;
    cleanup_ = nullptr;
}

}  // namespace installd
}  // namespace android
