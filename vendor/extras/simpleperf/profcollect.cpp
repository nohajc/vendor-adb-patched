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

#include <include/simpleperf_profcollect.hpp>

#include "ETMRecorder.h"
#include "command.h"
#include "event_attr.h"
#include "event_fd.h"
#include "event_type.h"

using namespace simpleperf;

bool HasSupport() {
  if (!ETMRecorder::GetInstance().CheckEtmSupport()) {
    return false;
  }
  const EventType* type = FindEventTypeByName("cs-etm", false);
  if (type == nullptr) {
    return false;
  }
  return IsEventAttrSupported(CreateDefaultPerfEventAttr(*type), type->name);
}

bool Record(const char* event_name, const char* output, float duration) {
  auto recordCmd = CreateCommandInstance("record");
  std::vector<std::string> args;
  args.push_back("-a");
  args.insert(args.end(), {"-e", event_name});
  args.insert(args.end(), {"--duration", std::to_string(duration)});
  args.insert(args.end(), {"-o", output});
  return recordCmd->Run(args);
}

bool Inject(const char* traceInput, const char* profileOutput) {
  auto injectCmd = CreateCommandInstance("inject");
  std::vector<std::string> args;
  args.insert(args.end(), {"-i", traceInput});
  args.insert(args.end(), {"-o", profileOutput});
  args.insert(args.end(), {"--output", "branch-list"});
  args.emplace_back("--exclude-perf");
  return injectCmd->Run(args);
}
