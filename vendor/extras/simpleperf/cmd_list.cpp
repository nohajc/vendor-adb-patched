/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <stdio.h>
#include <map>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>

#include "ETMRecorder.h"
#include "command.h"
#include "environment.h"
#include "event_attr.h"
#include "event_fd.h"
#include "event_selection_set.h"
#include "event_type.h"

namespace simpleperf {
namespace {

enum EventTypeStatus {
  NOT_SUPPORTED,
  MAY_NOT_SUPPORTED,
  SUPPORTED,
};

static EventTypeStatus IsEventTypeSupported(const EventType& event_type) {
  // Because PMU events are provided by kernel, we assume it's supported.
  if (event_type.IsPmuEvent()) {
    return EventTypeStatus::SUPPORTED;
  }
  if (event_type.type != PERF_TYPE_RAW) {
    perf_event_attr attr = CreateDefaultPerfEventAttr(event_type);
    // Exclude kernel to list supported events even when kernel recording isn't allowed.
    attr.exclude_kernel = 1;
    return IsEventAttrSupported(attr, event_type.name) ? EventTypeStatus::SUPPORTED
                                                       : EventTypeStatus::NOT_SUPPORTED;
  }
  if (event_type.limited_arch == "arm" && GetBuildArch() != ARCH_ARM &&
      GetBuildArch() != ARCH_ARM64) {
    return EventTypeStatus::NOT_SUPPORTED;
  }
  // Because the kernel may not check whether the raw event is supported by the cpu pmu.
  // We can't decide whether the raw event is supported by calling perf_event_open().
  // Instead, we can check if it can collect some real number.
  perf_event_attr attr = CreateDefaultPerfEventAttr(event_type);
  std::unique_ptr<EventFd> event_fd =
      EventFd::OpenEventFile(attr, gettid(), -1, nullptr, event_type.name, false);
  if (event_fd == nullptr) {
    return EventTypeStatus::NOT_SUPPORTED;
  }
  auto work_function = []() {
    TemporaryFile tmpfile;
    FILE* fp = fopen(tmpfile.path, "w");
    if (fp == nullptr) {
      return;
    }
    for (int i = 0; i < 10; ++i) {
      fprintf(fp, "output some data\n");
    }
    fclose(fp);
  };
  work_function();
  PerfCounter counter;
  if (!event_fd->ReadCounter(&counter)) {
    return EventTypeStatus::NOT_SUPPORTED;
  }
  // For raw events, we may not be able to detect whether it is supported on device.
  return (counter.value != 0u) ? EventTypeStatus::SUPPORTED : EventTypeStatus::MAY_NOT_SUPPORTED;
}

static void PrintEventTypesOfType(const std::string& type_name, const std::string& type_desc,
                                  const std::function<bool(const EventType&)>& is_type_fn) {
  printf("List of %s:\n", type_desc.c_str());
  if (GetBuildArch() == ARCH_ARM || GetBuildArch() == ARCH_ARM64) {
    if (type_name == "raw") {
      printf(
          // clang-format off
"  # Please refer to \"PMU common architectural and microarchitectural event numbers\"\n"
"  # and \"ARM recommendations for IMPLEMENTATION DEFINED event numbers\" listed in\n"
"  # ARMv8 manual for details.\n"
"  # A possible link is https://developer.arm.com/docs/ddi0487/latest/arm-architecture-reference-manual-armv8-for-armv8-a-architecture-profile.\n"
          // clang-format on
      );
    } else if (type_name == "cache") {
      printf("  # More cache events are available in `simpleperf list raw`.\n");
    }
  }
  auto callback = [&](const EventType& event_type) {
    if (is_type_fn(event_type)) {
      EventTypeStatus status = IsEventTypeSupported(event_type);
      if (status == EventTypeStatus::NOT_SUPPORTED) {
        return true;
      }
      printf("  %s", event_type.name.c_str());
      if (status == EventTypeStatus::MAY_NOT_SUPPORTED) {
        printf(" (may not supported)");
      }
      if (!event_type.description.empty()) {
        printf("\t\t# %s", event_type.description.c_str());
      }
      printf("\n");
    }
    return true;
  };
  EventTypeManager::Instance().ForEachType(callback);
  printf("\n");
}

class ListCommand : public Command {
 public:
  ListCommand()
      : Command("list", "list available event types",
                // clang-format off
"Usage: simpleperf list [options] [hw|sw|cache|raw|tracepoint|pmu]\n"
"       List all available event types.\n"
"       Filters can be used to show only event types belong to selected types:\n"
"         hw          hardware events\n"
"         sw          software events\n"
"         cache       hardware cache events\n"
"         raw         raw cpu pmu events\n"
"         tracepoint  tracepoint events\n"
"         cs-etm      coresight etm instruction tracing events\n"
"         pmu         system-specific pmu events\n"
"Options:\n"
"--show-features    Show features supported on the device, including:\n"
"                     dwarf-based-call-graph\n"
"                     trace-offcpu\n"
                // clang-format on
        ) {}

  bool Run(const std::vector<std::string>& args) override;

 private:
  void ShowFeatures();
};

bool ListCommand::Run(const std::vector<std::string>& args) {
  if (!CheckPerfEventLimit()) {
    return false;
  }

  static std::map<std::string, std::pair<std::string, std::function<bool(const EventType&)>>>
      type_map =
  { {"hw", {"hardware events", [](const EventType& e) { return e.type == PERF_TYPE_HARDWARE; }}},
    {"sw", {"software events", [](const EventType& e) { return e.type == PERF_TYPE_SOFTWARE; }}},
    {"cache", {"hw-cache events", [](const EventType& e) { return e.type == PERF_TYPE_HW_CACHE; }}},
    {"raw",
     {"raw events provided by cpu pmu",
      [](const EventType& e) { return e.type == PERF_TYPE_RAW; }}},
    {"tracepoint",
     {"tracepoint events", [](const EventType& e) { return e.type == PERF_TYPE_TRACEPOINT; }}},
#if defined(__arm__) || defined(__aarch64__)
    {"cs-etm",
     {"coresight etm events",
      [](const EventType& e) { return e.type == ETMRecorder::GetInstance().GetEtmEventType(); }}},
#endif
    {"pmu", {"pmu events", [](const EventType& e) { return e.IsPmuEvent(); }}},
  };

  std::vector<std::string> names;
  if (args.empty()) {
    for (auto& item : type_map) {
      names.push_back(item.first);
    }
  } else {
    for (auto& arg : args) {
      if (type_map.find(arg) != type_map.end()) {
        names.push_back(arg);
      } else if (arg == "--show-features") {
        ShowFeatures();
        return true;
      } else {
        LOG(ERROR) << "unknown event type category: " << arg << ", try using \"help list\"";
        return false;
      }
    }
  }

  for (auto& name : names) {
    auto it = type_map.find(name);
    PrintEventTypesOfType(name, it->second.first, it->second.second);
  }
  return true;
}

void ListCommand::ShowFeatures() {
  if (IsDwarfCallChainSamplingSupported()) {
    printf("dwarf-based-call-graph\n");
  }
  if (IsDumpingRegsForTracepointEventsSupported()) {
    printf("trace-offcpu\n");
  }
  if (IsSettingClockIdSupported()) {
    printf("set-clockid\n");
  }
}

}  // namespace

void RegisterListCommand() {
  RegisterCommand("list", [] { return std::unique_ptr<Command>(new ListCommand); });
}

}  // namespace simpleperf
