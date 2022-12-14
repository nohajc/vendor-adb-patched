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

#include <time.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>

#include <wakelock/wakelock.h>
#include <include/simpleperf_profcollect.hpp>

#include "ETMRecorder.h"
#include "command.h"
#include "event_attr.h"
#include "event_fd.h"
#include "event_type.h"

using namespace simpleperf;

bool HasDriverSupport() {
  bool result = ETMRecorder::GetInstance().IsETMDriverAvailable();
  LOG(INFO) << "HasDriverSupport result " << result;
  return result;
}

bool HasDeviceSupport() {
  auto result = ETMRecorder::GetInstance().CheckEtmSupport();
  if (!result.ok()) {
    LOG(INFO) << "HasDeviceSupport check failed: " << result.error();
    return false;
  }
  const EventType* type = FindEventTypeByName("cs-etm", false);
  if (type == nullptr) {
    LOG(INFO) << "HasDeviceSupport check failed: no etm event";
    return false;
  }
  bool ret = IsEventAttrSupported(CreateDefaultPerfEventAttr(*type), type->name);
  LOG(INFO) << "HasDeviceSupport result " << ret;
  return ret;
}

bool Record(const char* event_name, const char* output, float duration, const char* binary_filter) {
  LOG(INFO) << "Record " << event_name << ", duration " << duration << ", output " << output
            << ", binary_filter " << binary_filter;
  // The kernel may panic when trying to hibernate or hotplug CPUs while collecting
  // ETM data. So get wakelock to keep the CPUs on.
  auto wakelock = android::wakelock::WakeLock::tryGet("profcollectd");
  if (!wakelock) {
    LOG(ERROR) << "Record failed: Failed to request wakelock.";
    return false;
  }
  auto recordCmd = CreateCommandInstance("record");
  std::vector<std::string> args = {"-a",
                                   "-e",
                                   event_name,
                                   "--duration",
                                   std::to_string(duration),
                                   "--decode-etm",
                                   "--exclude-perf",
                                   "--binary",
                                   binary_filter,
                                   "-o",
                                   output};
  bool result = recordCmd->Run(args);
  LOG(INFO) << "Record result " << result;
  return result;
}

bool Inject(const char* traceInput, const char* profileOutput, const char* binary_filter) {
  LOG(INFO) << "Inject traceInput " << traceInput << ", profileOutput " << profileOutput
            << ", binary_filter " << binary_filter;
  auto injectCmd = CreateCommandInstance("inject");
  std::vector<std::string> args = {"-i",       traceInput,    "-o",       profileOutput,
                                   "--output", "branch-list", "--binary", binary_filter};
  bool result = injectCmd->Run(args);
  LOG(INFO) << "Inject result " << result;
  return result;
}

static android::base::unique_fd log_fd;
static android::base::LogFunction saved_log_func;

static void FileLogger(android::base::LogId id, android::base::LogSeverity severity,
                       const char* tag, const char* file, unsigned int line, const char* message) {
  if (log_fd.ok()) {
    static const char log_characters[] = "VDIWEFF";
    char severity_char = log_characters[severity];
    struct tm now;
    time_t t = time(nullptr);
    localtime_r(&t, &now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%m-%d %H:%M:%S", &now);
    std::string s = android::base::StringPrintf("%s %c %s %s:%u] %s\n", tag, severity_char,
                                                timestamp, file, line, message);
    WriteStringToFd(s, log_fd);
  }
  saved_log_func(id, severity, tag, file, line, message);
}

void SetLogFile(const char* filename) {
  int fd = TEMP_FAILURE_RETRY(open(filename, O_APPEND | O_CREAT | O_WRONLY | O_CLOEXEC, 0600));
  if (fd == -1) {
    PLOG(ERROR) << "failed to open " << filename;
    return;
  }
  log_fd.reset(fd);
  saved_log_func = SetLogger(FileLogger);
}

void ResetLogFile() {
  log_fd.reset();
  SetLogger(std::move(saved_log_func));
}
