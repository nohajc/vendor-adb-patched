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

#include <wakelock/wakelock.h>
#include <include/simpleperf_profcollect.hpp>

#include "ETMRecorder.h"
#include "command.h"
#include "event_attr.h"
#include "event_fd.h"
#include "event_type.h"

using namespace simpleperf;

bool HasDriverSupport() {
  return ETMRecorder::GetInstance().IsETMDriverAvailable();
}

bool HasDeviceSupport() {
  auto result = ETMRecorder::GetInstance().CheckEtmSupport();
  if (!result.ok()) {
    LOG(DEBUG) << result.error();
    return false;
  }
  const EventType* type = FindEventTypeByName("cs-etm", false);
  if (type == nullptr) {
    return false;
  }
  return IsEventAttrSupported(CreateDefaultPerfEventAttr(*type), type->name);
}

bool Record(const char* event_name, const char* output, float duration) {
  // The kernel may panic when trying to hibernate or hotplug CPUs while collecting
  // ETM data. So get wakelock to keep the CPUs on.
  auto wakelock = android::wakelock::WakeLock::tryGet("profcollectd");
  if (!wakelock) {
    LOG(ERROR) << "Failed to request wakelock.";
    return false;
  }
  auto recordCmd = CreateCommandInstance("record");
  std::vector<std::string> args;
  args.push_back("-a");
  args.insert(args.end(), {"-e", event_name});
  args.insert(args.end(), {"--duration", std::to_string(duration)});
  args.insert(args.end(), {"-o", output});
  return recordCmd->Run(args);
}

bool Inject(const char* traceInput, const char* profileOutput, const char* binary_filter) {
  auto injectCmd = CreateCommandInstance("inject");
  std::vector<std::string> args;
  args.insert(args.end(), {"-i", traceInput});
  args.insert(args.end(), {"-o", profileOutput});
  if (binary_filter) {
    args.insert(args.end(), {"--binary", binary_filter});
  }
  args.insert(args.end(), {"--output", "branch-list"});
  args.emplace_back("--exclude-perf");
  return injectCmd->Run(args);
}
