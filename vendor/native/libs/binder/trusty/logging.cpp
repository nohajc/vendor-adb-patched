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

#define TLOG_TAG "libbinder"

#include "android-base/logging.h"

#include <trusty_log.h>
#include <iostream>
#include <string>

#include <android-base/macros.h>
#include <android-base/strings.h>

namespace android {
namespace base {

static const char* GetFileBasename(const char* file) {
    const char* last_slash = strrchr(file, '/');
    if (last_slash != nullptr) {
        return last_slash + 1;
    }
    return file;
}

// This splits the message up line by line, by calling log_function with a pointer to the start of
// each line and the size up to the newline character.  It sends size = -1 for the final line.
template <typename F, typename... Args>
static void SplitByLines(const char* msg, const F& log_function, Args&&... args) {
    const char* newline;
    while ((newline = strchr(msg, '\n')) != nullptr) {
        log_function(msg, newline - msg, args...);
        msg = newline + 1;
    }

    log_function(msg, -1, args...);
}

void DefaultAborter(const char* abort_message) {
    TLOGC("aborting: %s\n", abort_message);
    abort();
}

static void TrustyLogLine(const char* msg, int /*length*/, android::base::LogSeverity severity,
                          const char* tag) {
    switch (severity) {
        case VERBOSE:
        case DEBUG:
            TLOGD("%s: %s\n", tag, msg);
            break;
        case INFO:
            TLOGI("%s: %s\n", tag, msg);
            break;
        case WARNING:
            TLOGW("%s: %s\n", tag, msg);
            break;
        case ERROR:
            TLOGE("%s: %s\n", tag, msg);
            break;
        case FATAL_WITHOUT_ABORT:
        case FATAL:
            TLOGC("%s: %s\n", tag, msg);
            break;
    }
}

void TrustyLogger(android::base::LogId, android::base::LogSeverity severity, const char* tag,
                  const char*, unsigned int, const char* full_message) {
    SplitByLines(full_message, TrustyLogLine, severity, tag);
}

// This indirection greatly reduces the stack impact of having lots of
// checks/logging in a function.
class LogMessageData {
public:
    LogMessageData(const char* file, unsigned int line, LogSeverity severity, const char* tag,
                   int error)
          : file_(GetFileBasename(file)),
            line_number_(line),
            severity_(severity),
            tag_(tag),
            error_(error) {}

    const char* GetFile() const { return file_; }

    unsigned int GetLineNumber() const { return line_number_; }

    LogSeverity GetSeverity() const { return severity_; }

    const char* GetTag() const { return tag_; }

    int GetError() const { return error_; }

    std::ostream& GetBuffer() { return buffer_; }

    std::string ToString() const { return buffer_.str(); }

private:
    std::ostringstream buffer_;
    const char* const file_;
    const unsigned int line_number_;
    const LogSeverity severity_;
    const char* const tag_;
    const int error_;

    DISALLOW_COPY_AND_ASSIGN(LogMessageData);
};

LogMessage::LogMessage(const char* file, unsigned int line, LogId, LogSeverity severity,
                       const char* tag, int error)
      : LogMessage(file, line, severity, tag, error) {}

LogMessage::LogMessage(const char* file, unsigned int line, LogSeverity severity, const char* tag,
                       int error)
      : data_(new LogMessageData(file, line, severity, tag, error)) {}

LogMessage::~LogMessage() {
    // Check severity again. This is duplicate work wrt/ LOG macros, but not LOG_STREAM.
    if (!WOULD_LOG(data_->GetSeverity())) {
        return;
    }

    // Finish constructing the message.
    if (data_->GetError() != -1) {
        data_->GetBuffer() << ": " << strerror(data_->GetError());
    }
    std::string msg(data_->ToString());

    LogLine(data_->GetFile(), data_->GetLineNumber(), data_->GetSeverity(), data_->GetTag(),
            msg.c_str());

    // Abort if necessary.
    if (data_->GetSeverity() == FATAL) {
        DefaultAborter(msg.c_str());
    }
}

std::ostream& LogMessage::stream() {
    return data_->GetBuffer();
}

void LogMessage::LogLine(const char* file, unsigned int line, LogSeverity severity, const char* tag,
                         const char* message) {
    TrustyLogger(DEFAULT, severity, tag ?: "<unknown>", file, line, message);
}

bool ShouldLog(LogSeverity /*severity*/, const char* /*tag*/) {
    // This is controlled by Trusty's log level.
    return true;
}

} // namespace base
} // namespace android
