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

#include "PipeRelay.h"

#include <sys/poll.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <optional>

#include <android-base/unique_fd.h>

using android::base::borrowed_fd;
using android::base::Result;
using android::base::unique_fd;
using std::chrono_literals::operator""ms;

namespace android {
namespace lshal {
Result<std::unique_ptr<PipeRelay>> PipeRelay::create(std::ostream& os,
                                                     const NullableOStream<std::ostream>& err,
                                                     const std::string& fqName) {
    auto pipeRelay = std::unique_ptr<PipeRelay>(new PipeRelay());
    unique_fd rfd;
    if (!android::base::Pipe(&rfd, &pipeRelay->mWrite)) {
        return android::base::ErrnoError() << "pipe()";
    }
    // Workaround for b/111997867: need a separate FD trigger because rfd can't receive POLLHUP
    // when the write end is closed after the write end was sent through hwbinder.
    unique_fd rfdTrigger;
    if (!android::base::Pipe(&rfdTrigger, &pipeRelay->mWriteTrigger)) {
        return android::base::ErrnoError() << "pipe() for trigger";
    }
    pipeRelay->mThread =
            std::make_unique<std::thread>(&PipeRelay::thread, std::move(rfd), std::move(rfdTrigger),
                                          &os, &err, fqName);
    return pipeRelay;
}

void PipeRelay::thread(unique_fd rfd, unique_fd rfdTrigger, std::ostream* out,
                       const NullableOStream<std::ostream>* err, std::string fqName) {
    while (true) {
        pollfd pfd[2];
        pfd[0] = {.fd = rfd.get(), .events = POLLIN};
        pfd[1] = {.fd = rfdTrigger.get(), .events = 0};

        int pollRes = poll(pfd, arraysize(pfd), -1 /* infinite timeout */);
        if (pollRes < 0) {
            int savedErrno = errno;
            (*err) << "debug " << fqName << ": poll() failed: " << strerror(savedErrno)
                   << std::endl;
            break;
        }

        if (pfd[0].revents & POLLIN) {
            char buffer[1024];
            ssize_t n = TEMP_FAILURE_RETRY(read(rfd.get(), buffer, sizeof(buffer)));
            if (n < 0) {
                int savedErrno = errno;
                (*err) << "debug " << fqName << ": read() failed: " << strerror(savedErrno)
                       << std::endl;
                break;
            }
            if (n == 0) {
                (*err) << "Warning: debug " << fqName << ": poll() indicates POLLIN but no data"
                       << std::endl;
                continue;
            }
            out->write(buffer, n);
            continue;
        }
        if (pfd[0].revents & POLLHUP) {
            break;
        }
        if (pfd[1].revents & POLLHUP) {
            // ~PipeRelay is called on the main thread. |mWrite| has been flushed and closed.
            // Ensure that our read end of the pipe doesn't have pending data, then exit.
            if ((pfd[0].revents & POLLIN) == 0) {
                break;
            }
        }
    }
}

PipeRelay::~PipeRelay() {
    mWrite.reset();
    mWriteTrigger.reset();
    if (mThread != nullptr && mThread->joinable()) {
        mThread->join();
    }
}

} // namespace lshal
} // namespace android
