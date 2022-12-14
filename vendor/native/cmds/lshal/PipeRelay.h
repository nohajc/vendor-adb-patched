/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <thread>

#include <android-base/macros.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <ostream>

#include "NullableOStream.h"

namespace android {
namespace lshal {

/**
 * Creates a pipe and spawns a thread that relays any data
 * written to the "write"-end of the pair to the specified output stream "os".
 */
struct PipeRelay {
    static android::base::Result<std::unique_ptr<PipeRelay>> create(
            std::ostream& os, const NullableOStream<std::ostream>& err, const std::string& fqName);
    ~PipeRelay();

    // Returns the file descriptor corresponding to the "write"-end of the
    // connection.
    android::base::borrowed_fd fd() const { return mWrite; }

private:
    PipeRelay() = default;
    DISALLOW_COPY_AND_ASSIGN(PipeRelay);
    static void thread(android::base::unique_fd rfd, android::base::unique_fd rfdTrigger,
                       std::ostream* out, const NullableOStream<std::ostream>* err,
                       std::string fqName);

    android::base::unique_fd mWrite;
    android::base::unique_fd mWriteTrigger;
    std::unique_ptr<std::thread> mThread;
};

}  // namespace lshal
}  // namespace android
