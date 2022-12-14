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

#include "event_selection_set.h"

#include <algorithm>
#include <atomic>
#include <thread>
#include <unordered_map>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "ETMRecorder.h"
#include "IOEventLoop.h"
#include "RecordReadThread.h"
#include "environment.h"
#include "event_attr.h"
#include "event_type.h"
#include "perf_regs.h"
#include "tracing.h"
#include "utils.h"

namespace simpleperf {

using android::base::StringPrintf;

bool IsBranchSamplingSupported() {
  const EventType* type = FindEventTypeByName("cpu-cycles");
  if (type == nullptr) {
    return false;
  }
  perf_event_attr attr = CreateDefaultPerfEventAttr(*type);
  attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
  attr.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
  return IsEventAttrSupported(attr, type->name);
}

bool IsDwarfCallChainSamplingSupported() {
  const EventType* type = FindEventTypeByName("cpu-clock");
  if (type == nullptr) {
    return false;
  }
  perf_event_attr attr = CreateDefaultPerfEventAttr(*type);
  attr.sample_type |= PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER;
  attr.exclude_callchain_user = 1;
  attr.sample_regs_user = GetSupportedRegMask(GetBuildArch());
  attr.sample_stack_user = 8192;
  return IsEventAttrSupported(attr, type->name);
}

bool IsDumpingRegsForTracepointEventsSupported() {
  if (auto version = GetKernelVersion(); version && version.value() >= std::make_pair(4, 2)) {
    // Kernel >= 4.2 has patch "5b09a094f2 arm64: perf: Fix callchain parse error with kernel
    // tracepoint events". So no need to test.
    return true;
  }
  const EventType* event_type = FindEventTypeByName("sched:sched_switch", false);
  if (event_type == nullptr) {
    return false;
  }
  std::atomic<bool> done(false);
  std::atomic<pid_t> thread_id(0);
  std::thread thread([&]() {
    thread_id = gettid();
    while (!done) {
      usleep(1);
    }
    usleep(1);  // Make a sched out to generate one sample.
  });
  while (thread_id == 0) {
    usleep(1);
  }
  perf_event_attr attr = CreateDefaultPerfEventAttr(*event_type);
  attr.freq = 0;
  attr.sample_period = 1;
  std::unique_ptr<EventFd> event_fd =
      EventFd::OpenEventFile(attr, thread_id, -1, nullptr, event_type->name);
  if (event_fd == nullptr || !event_fd->CreateMappedBuffer(4, true)) {
    done = true;
    thread.join();
    return false;
  }
  done = true;
  thread.join();

  // There are small chances that we don't see samples immediately after joining the thread on
  // cuttlefish, probably due to data synchronization between cpus. To avoid flaky tests, use a
  // loop to wait for samples.
  for (int timeout = 0; timeout < 1000; timeout++) {
    std::vector<char> buffer = event_fd->GetAvailableMmapData();
    std::vector<std::unique_ptr<Record>> records =
        ReadRecordsFromBuffer(attr, buffer.data(), buffer.size());
    for (auto& r : records) {
      if (r->type() == PERF_RECORD_SAMPLE) {
        auto& record = *static_cast<SampleRecord*>(r.get());
        return record.ip_data.ip != 0;
      }
    }
    usleep(1);
  }
  return false;
}

bool IsSettingClockIdSupported() {
  // Do the real check only once and keep the result in a static variable.
  static int is_supported = -1;
  if (is_supported == -1) {
    const EventType* type = FindEventTypeByName("cpu-clock");
    if (type == nullptr) {
      is_supported = 0;
    } else {
      // Check if the kernel supports setting clockid, which was added in kernel 4.0. Just check
      // with one clockid is enough. Because all needed clockids were supported before kernel 4.0.
      perf_event_attr attr = CreateDefaultPerfEventAttr(*type);
      attr.use_clockid = 1;
      attr.clockid = CLOCK_MONOTONIC;
      is_supported = IsEventAttrSupported(attr, type->name) ? 1 : 0;
    }
  }
  return is_supported;
}

bool IsMmap2Supported() {
  const EventType* type = FindEventTypeByName("cpu-clock");
  if (type == nullptr) {
    return false;
  }
  perf_event_attr attr = CreateDefaultPerfEventAttr(*type);
  attr.mmap2 = 1;
  return IsEventAttrSupported(attr, type->name);
}

std::string AddrFilter::ToString() const {
  switch (type) {
    case FILE_RANGE:
      return StringPrintf("filter 0x%" PRIx64 "/0x%" PRIx64 "@%s", addr, size, file_path.c_str());
    case AddrFilter::FILE_START:
      return StringPrintf("start 0x%" PRIx64 "@%s", addr, file_path.c_str());
    case AddrFilter::FILE_STOP:
      return StringPrintf("stop 0x%" PRIx64 "@%s", addr, file_path.c_str());
    case AddrFilter::KERNEL_RANGE:
      return StringPrintf("filter 0x%" PRIx64 "/0x%" PRIx64, addr, size);
    case AddrFilter::KERNEL_START:
      return StringPrintf("start 0x%" PRIx64, addr);
    case AddrFilter::KERNEL_STOP:
      return StringPrintf("stop 0x%" PRIx64, addr);
  }
}

EventSelectionSet::EventSelectionSet(bool for_stat_cmd)
    : for_stat_cmd_(for_stat_cmd), loop_(new IOEventLoop) {}

EventSelectionSet::~EventSelectionSet() {}

bool EventSelectionSet::BuildAndCheckEventSelection(const std::string& event_name, bool first_event,
                                                    EventSelection* selection) {
  std::unique_ptr<EventTypeAndModifier> event_type = ParseEventType(event_name);
  if (event_type == nullptr) {
    return false;
  }
  if (for_stat_cmd_) {
    if (event_type->event_type.name == "cpu-clock" || event_type->event_type.name == "task-clock") {
      if (event_type->exclude_user || event_type->exclude_kernel) {
        LOG(ERROR) << "Modifier u and modifier k used in event type " << event_type->event_type.name
                   << " are not supported by the kernel.";
        return false;
      }
    }
  }
  selection->event_type_modifier = *event_type;
  selection->event_attr = CreateDefaultPerfEventAttr(event_type->event_type);
  selection->event_attr.exclude_user = event_type->exclude_user;
  selection->event_attr.exclude_kernel = event_type->exclude_kernel;
  selection->event_attr.exclude_hv = event_type->exclude_hv;
  selection->event_attr.exclude_host = event_type->exclude_host;
  selection->event_attr.exclude_guest = event_type->exclude_guest;
  selection->event_attr.precise_ip = event_type->precise_ip;
  if (IsEtmEventType(event_type->event_type.type)) {
    auto& etm_recorder = ETMRecorder::GetInstance();
    if (!etm_recorder.CheckEtmSupport()) {
      return false;
    }
    ETMRecorder::GetInstance().SetEtmPerfEventAttr(&selection->event_attr);
  }
  bool set_default_sample_freq = false;
  if (!for_stat_cmd_) {
    if (event_type->event_type.type == PERF_TYPE_TRACEPOINT) {
      selection->event_attr.freq = 0;
      selection->event_attr.sample_period = DEFAULT_SAMPLE_PERIOD_FOR_TRACEPOINT_EVENT;
    } else if (IsEtmEventType(event_type->event_type.type)) {
      // ETM recording has no sample frequency to adjust. Using sample frequency only wastes time
      // enabling/disabling etm devices. So don't adjust frequency by default.
      selection->event_attr.freq = 0;
      selection->event_attr.sample_period = 1;
    } else {
      selection->event_attr.freq = 1;
      // Set default sample freq here may print msg "Adjust sample freq to max allowed sample
      // freq". But this is misleading. Because default sample freq may not be the final sample
      // freq we use. So use minimum sample freq (1) here.
      selection->event_attr.sample_freq = 1;
      set_default_sample_freq = true;
    }
    // We only need to dump mmap and comm records for the first event type. Because all event types
    // are monitoring the same processes.
    if (first_event) {
      selection->event_attr.mmap = 1;
      selection->event_attr.comm = 1;
      if (IsMmap2Supported()) {
        selection->event_attr.mmap2 = 1;
      }
    }
  }
  // PMU events are provided by kernel, so they should be supported
  if (!event_type->event_type.IsPmuEvent() &&
      !IsEventAttrSupported(selection->event_attr, selection->event_type_modifier.name)) {
    LOG(ERROR) << "Event type '" << event_type->name << "' is not supported on the device";
    return false;
  }
  if (set_default_sample_freq) {
    selection->event_attr.sample_freq = DEFAULT_SAMPLE_FREQ_FOR_NONTRACEPOINT_EVENT;
  }

  selection->event_fds.clear();

  for (const auto& group : groups_) {
    for (const auto& sel : group) {
      if (sel.event_type_modifier.name == selection->event_type_modifier.name) {
        LOG(ERROR) << "Event type '" << sel.event_type_modifier.name << "' appears more than once";
        return false;
      }
    }
  }
  return true;
}

bool EventSelectionSet::AddEventType(const std::string& event_name, size_t* group_id) {
  return AddEventGroup(std::vector<std::string>(1, event_name), group_id);
}

bool EventSelectionSet::AddEventGroup(const std::vector<std::string>& event_names,
                                      size_t* group_id) {
  EventSelectionGroup group;
  bool first_event = groups_.empty();
  bool first_in_group = true;
  for (const auto& event_name : event_names) {
    EventSelection selection;
    if (!BuildAndCheckEventSelection(event_name, first_event, &selection)) {
      return false;
    }
    if (IsEtmEventType(selection.event_attr.type)) {
      has_aux_trace_ = true;
    }
    if (first_in_group) {
      auto& event_type = selection.event_type_modifier.event_type;
      if (event_type.IsPmuEvent()) {
        selection.allowed_cpus = event_type.GetPmuCpumask();
      }
    }
    first_event = false;
    first_in_group = false;
    group.push_back(std::move(selection));
  }
  groups_.push_back(std::move(group));
  UnionSampleType();
  if (group_id != nullptr) {
    *group_id = groups_.size() - 1;
  }
  return true;
}

std::vector<const EventType*> EventSelectionSet::GetEvents() const {
  std::vector<const EventType*> result;
  for (const auto& group : groups_) {
    for (const auto& selection : group) {
      result.push_back(&selection.event_type_modifier.event_type);
    }
  }
  return result;
}

std::vector<const EventType*> EventSelectionSet::GetTracepointEvents() const {
  std::vector<const EventType*> result;
  for (const auto& group : groups_) {
    for (const auto& selection : group) {
      if (selection.event_type_modifier.event_type.type == PERF_TYPE_TRACEPOINT) {
        result.push_back(&selection.event_type_modifier.event_type);
      }
    }
  }
  return result;
}

bool EventSelectionSet::ExcludeKernel() const {
  for (const auto& group : groups_) {
    for (const auto& selection : group) {
      if (!selection.event_type_modifier.exclude_kernel) {
        return false;
      }
    }
  }
  return true;
}

std::vector<EventAttrWithId> EventSelectionSet::GetEventAttrWithId() const {
  std::vector<EventAttrWithId> result;
  for (const auto& group : groups_) {
    for (const auto& selection : group) {
      EventAttrWithId attr_id;
      attr_id.attr = &selection.event_attr;
      for (const auto& fd : selection.event_fds) {
        attr_id.ids.push_back(fd->Id());
      }
      result.push_back(attr_id);
    }
  }
  return result;
}

std::unordered_map<uint64_t, std::string> EventSelectionSet::GetEventNamesById() const {
  std::unordered_map<uint64_t, std::string> result;
  for (const auto& group : groups_) {
    for (const auto& selection : group) {
      for (const auto& fd : selection.event_fds) {
        result[fd->Id()] = selection.event_type_modifier.name;
      }
    }
  }
  return result;
}

// Union the sample type of different event attrs can make reading sample
// records in perf.data easier.
void EventSelectionSet::UnionSampleType() {
  uint64_t sample_type = 0;
  for (const auto& group : groups_) {
    for (const auto& selection : group) {
      sample_type |= selection.event_attr.sample_type;
    }
  }
  for (auto& group : groups_) {
    for (auto& selection : group) {
      selection.event_attr.sample_type = sample_type;
    }
  }
}

void EventSelectionSet::SetEnableOnExec(bool enable) {
  for (auto& group : groups_) {
    for (auto& selection : group) {
      // If sampling is enabled on exec, then it is disabled at startup,
      // otherwise it should be enabled at startup. Don't use
      // ioctl(PERF_EVENT_IOC_ENABLE) to enable it after perf_event_open().
      // Because some android kernels can't handle ioctl() well when cpu-hotplug
      // happens. See http://b/25193162.
      if (enable) {
        selection.event_attr.enable_on_exec = 1;
        selection.event_attr.disabled = 1;
      } else {
        selection.event_attr.enable_on_exec = 0;
        selection.event_attr.disabled = 0;
      }
    }
  }
}

bool EventSelectionSet::GetEnableOnExec() {
  for (const auto& group : groups_) {
    for (const auto& selection : group) {
      if (selection.event_attr.enable_on_exec == 0) {
        return false;
      }
    }
  }
  return true;
}

void EventSelectionSet::SampleIdAll() {
  for (auto& group : groups_) {
    for (auto& selection : group) {
      selection.event_attr.sample_id_all = 1;
    }
  }
}

void EventSelectionSet::SetSampleSpeed(size_t group_id, const SampleSpeed& speed) {
  CHECK_LT(group_id, groups_.size());
  for (auto& selection : groups_[group_id]) {
    if (speed.UseFreq()) {
      selection.event_attr.freq = 1;
      selection.event_attr.sample_freq = speed.sample_freq;
    } else {
      selection.event_attr.freq = 0;
      selection.event_attr.sample_period = speed.sample_period;
    }
  }
}

bool EventSelectionSet::SetBranchSampling(uint64_t branch_sample_type) {
  if (branch_sample_type != 0 &&
      (branch_sample_type & (PERF_SAMPLE_BRANCH_ANY | PERF_SAMPLE_BRANCH_ANY_CALL |
                             PERF_SAMPLE_BRANCH_ANY_RETURN | PERF_SAMPLE_BRANCH_IND_CALL)) == 0) {
    LOG(ERROR) << "Invalid branch_sample_type: 0x" << std::hex << branch_sample_type;
    return false;
  }
  if (branch_sample_type != 0 && !IsBranchSamplingSupported()) {
    LOG(ERROR) << "branch stack sampling is not supported on this device.";
    return false;
  }
  for (auto& group : groups_) {
    for (auto& selection : group) {
      perf_event_attr& attr = selection.event_attr;
      if (branch_sample_type != 0) {
        attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
      } else {
        attr.sample_type &= ~PERF_SAMPLE_BRANCH_STACK;
      }
      attr.branch_sample_type = branch_sample_type;
    }
  }
  return true;
}

void EventSelectionSet::EnableFpCallChainSampling() {
  for (auto& group : groups_) {
    for (auto& selection : group) {
      selection.event_attr.sample_type |= PERF_SAMPLE_CALLCHAIN;
    }
  }
}

bool EventSelectionSet::EnableDwarfCallChainSampling(uint32_t dump_stack_size) {
  if (!IsDwarfCallChainSamplingSupported()) {
    LOG(ERROR) << "dwarf callchain sampling is not supported on this device.";
    return false;
  }
  for (auto& group : groups_) {
    for (auto& selection : group) {
      selection.event_attr.sample_type |=
          PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER;
      selection.event_attr.exclude_callchain_user = 1;
      selection.event_attr.sample_regs_user = GetSupportedRegMask(GetMachineArch());
      selection.event_attr.sample_stack_user = dump_stack_size;
    }
  }
  return true;
}

void EventSelectionSet::SetInherit(bool enable) {
  for (auto& group : groups_) {
    for (auto& selection : group) {
      selection.event_attr.inherit = (enable ? 1 : 0);
    }
  }
}

void EventSelectionSet::SetClockId(int clock_id) {
  for (auto& group : groups_) {
    for (auto& selection : group) {
      selection.event_attr.use_clockid = 1;
      selection.event_attr.clockid = clock_id;
    }
  }
}

bool EventSelectionSet::NeedKernelSymbol() const {
  return !ExcludeKernel();
}

void EventSelectionSet::SetRecordNotExecutableMaps(bool record) {
  // We only need to dump non-executable mmap records for the first event type.
  groups_[0][0].event_attr.mmap_data = record ? 1 : 0;
}

bool EventSelectionSet::RecordNotExecutableMaps() const {
  return groups_[0][0].event_attr.mmap_data == 1;
}

void EventSelectionSet::WakeupPerSample() {
  for (auto& group : groups_) {
    for (auto& selection : group) {
      selection.event_attr.watermark = 0;
      selection.event_attr.wakeup_events = 1;
    }
  }
}

bool EventSelectionSet::SetTracepointFilter(const std::string& filter) {
  // 1. Find the tracepoint event to set filter.
  EventSelection* selection = nullptr;
  if (!groups_.empty()) {
    auto& group = groups_.back();
    if (group.size() == 1) {
      if (group[0].event_attr.type == PERF_TYPE_TRACEPOINT) {
        selection = &group[0];
      }
    }
  }
  if (selection == nullptr) {
    LOG(ERROR) << "No tracepoint event before filter: " << filter;
    return false;
  }

  // 2. Check the format of the filter.
  bool use_quote = false;
  // Quotes are needed for string operands in kernel >= 4.19, probably after patch "tracing: Rewrite
  // filter logic to be simpler and faster".
  if (auto version = GetKernelVersion(); version && version.value() >= std::make_pair(4, 19)) {
    use_quote = true;
  }

  FieldNameSet used_fields;
  auto adjusted_filter = AdjustTracepointFilter(filter, use_quote, &used_fields);
  if (!adjusted_filter) {
    return false;
  }

  // 3. Check if used fields are available in the tracepoint event.
  auto& event_type = selection->event_type_modifier.event_type;
  if (auto opt_fields = GetFieldNamesForTracepointEvent(event_type); opt_fields) {
    FieldNameSet& fields = opt_fields.value();
    for (const auto& field : used_fields) {
      if (fields.find(field) == fields.end()) {
        LOG(ERROR) << "field name " << field << " used in \"" << filter << "\" doesn't exist in "
                   << event_type.name << ". Available fields are "
                   << android::base::Join(fields, ",");
        return false;
      }
    }
  }

  // 4. Connect the filter to the event.
  selection->tracepoint_filter = adjusted_filter.value();
  return true;
}

static bool CheckIfCpusOnline(const std::vector<int>& cpus) {
  std::vector<int> online_cpus = GetOnlineCpus();
  for (const auto& cpu : cpus) {
    if (std::find(online_cpus.begin(), online_cpus.end(), cpu) == online_cpus.end()) {
      LOG(ERROR) << "cpu " << cpu << " is not online.";
      return false;
    }
  }
  return true;
}

bool EventSelectionSet::OpenEventFilesOnGroup(EventSelectionGroup& group, pid_t tid, int cpu,
                                              std::string* failed_event_type) {
  std::vector<std::unique_ptr<EventFd>> event_fds;
  // Given a tid and cpu, events on the same group should be all opened
  // successfully or all failed to open.
  EventFd* group_fd = nullptr;
  for (auto& selection : group) {
    std::unique_ptr<EventFd> event_fd = EventFd::OpenEventFile(
        selection.event_attr, tid, cpu, group_fd, selection.event_type_modifier.name, false);
    if (!event_fd) {
      *failed_event_type = selection.event_type_modifier.name;
      return false;
    }
    LOG(VERBOSE) << "OpenEventFile for " << event_fd->Name();
    event_fds.push_back(std::move(event_fd));
    if (group_fd == nullptr) {
      group_fd = event_fds.back().get();
    }
  }
  for (size_t i = 0; i < group.size(); ++i) {
    group[i].event_fds.push_back(std::move(event_fds[i]));
  }
  return true;
}

static std::set<pid_t> PrepareThreads(const std::set<pid_t>& processes,
                                      const std::set<pid_t>& threads) {
  std::set<pid_t> result = threads;
  for (auto& pid : processes) {
    std::vector<pid_t> tids = GetThreadsInProcess(pid);
    result.insert(tids.begin(), tids.end());
  }
  return result;
}

bool EventSelectionSet::OpenEventFiles(const std::vector<int>& cpus) {
  std::vector<int> monitored_cpus;
  if (cpus.empty()) {
    monitored_cpus = GetOnlineCpus();
  } else if (cpus.size() == 1 && cpus[0] == -1) {
    monitored_cpus = {-1};
  } else {
    if (!CheckIfCpusOnline(cpus)) {
      return false;
    }
    monitored_cpus = cpus;
  }
  std::set<pid_t> threads = PrepareThreads(processes_, threads_);
  for (auto& group : groups_) {
    size_t success_count = 0;
    std::string failed_event_type;
    for (const auto tid : threads) {
      const std::vector<int>* pcpus = &monitored_cpus;
      if (!group[0].allowed_cpus.empty()) {
        // override cpu list if event's PMU has a cpumask as those PMUs are
        // agnostic to cpu and it's meaningless to specify cpus for them.
        pcpus = &group[0].allowed_cpus;
      }
      for (const auto& cpu : *pcpus) {
        if (OpenEventFilesOnGroup(group, tid, cpu, &failed_event_type)) {
          success_count++;
        }
      }
    }
    // We can't guarantee to open perf event file successfully for each thread on each cpu.
    // Because threads may exit between PrepareThreads() and OpenEventFilesOnGroup(), and
    // cpus may be offlined between GetOnlineCpus() and OpenEventFilesOnGroup().
    // So we only check that we can at least monitor one thread for each event group.
    if (success_count == 0) {
      int error_number = errno;
      PLOG(ERROR) << "failed to open perf event file for event_type " << failed_event_type;
      if (error_number == EMFILE) {
        LOG(ERROR) << "Please increase hard limit of open file numbers.";
      }
      return false;
    }
  }
  return ApplyFilters();
}

bool EventSelectionSet::ApplyFilters() {
  return ApplyAddrFilters() && ApplyTracepointFilters();
}

bool EventSelectionSet::ApplyAddrFilters() {
  if (addr_filters_.empty()) {
    return true;
  }
  if (!has_aux_trace_) {
    LOG(ERROR) << "addr filters only take effect in cs-etm instruction tracing";
    return false;
  }

  // Check filter count limit.
  size_t required_etm_filter_count = 0;
  for (auto& filter : addr_filters_) {
    // A range filter needs two etm filters.
    required_etm_filter_count +=
        (filter.type == AddrFilter::FILE_RANGE || filter.type == AddrFilter::KERNEL_RANGE) ? 2 : 1;
  }
  size_t etm_filter_count = ETMRecorder::GetInstance().GetAddrFilterPairs() * 2;
  if (etm_filter_count < required_etm_filter_count) {
    LOG(ERROR) << "needed " << required_etm_filter_count << " etm filters, but only "
               << etm_filter_count << " filters are available.";
    return false;
  }

  std::string filter_str;
  for (auto& filter : addr_filters_) {
    if (!filter_str.empty()) {
      filter_str += ',';
    }
    filter_str += filter.ToString();
  }

  for (auto& group : groups_) {
    for (auto& selection : group) {
      if (IsEtmEventType(selection.event_type_modifier.event_type.type)) {
        for (auto& event_fd : selection.event_fds) {
          if (!event_fd->SetFilter(filter_str)) {
            return false;
          }
        }
      }
    }
  }
  return true;
}

bool EventSelectionSet::ApplyTracepointFilters() {
  for (auto& group : groups_) {
    for (auto& selection : group) {
      if (!selection.tracepoint_filter.empty()) {
        for (auto& event_fd : selection.event_fds) {
          if (!event_fd->SetFilter(selection.tracepoint_filter)) {
            return false;
          }
        }
      }
    }
  }
  return true;
}

static bool ReadCounter(EventFd* event_fd, CounterInfo* counter) {
  if (!event_fd->ReadCounter(&counter->counter)) {
    return false;
  }
  counter->tid = event_fd->ThreadId();
  counter->cpu = event_fd->Cpu();
  return true;
}

bool EventSelectionSet::ReadCounters(std::vector<CountersInfo>* counters) {
  counters->clear();
  for (size_t i = 0; i < groups_.size(); ++i) {
    for (auto& selection : groups_[i]) {
      CountersInfo counters_info;
      counters_info.group_id = i;
      counters_info.event_name = selection.event_type_modifier.event_type.name;
      counters_info.event_modifier = selection.event_type_modifier.modifier;
      counters_info.counters = selection.hotplugged_counters;
      for (auto& event_fd : selection.event_fds) {
        CounterInfo counter;
        if (!ReadCounter(event_fd.get(), &counter)) {
          return false;
        }
        counters_info.counters.push_back(counter);
      }
      counters->push_back(counters_info);
    }
  }
  return true;
}

bool EventSelectionSet::MmapEventFiles(size_t min_mmap_pages, size_t max_mmap_pages,
                                       size_t aux_buffer_size, size_t record_buffer_size,
                                       bool allow_cutting_samples, bool exclude_perf) {
  record_read_thread_.reset(new simpleperf::RecordReadThread(
      record_buffer_size, groups_[0][0].event_attr, min_mmap_pages, max_mmap_pages, aux_buffer_size,
      allow_cutting_samples, exclude_perf));
  return true;
}

bool EventSelectionSet::PrepareToReadMmapEventData(const std::function<bool(Record*)>& callback) {
  // Prepare record callback function.
  record_callback_ = callback;
  if (!record_read_thread_->RegisterDataCallback(*loop_,
                                                 [this]() { return ReadMmapEventData(true); })) {
    return false;
  }
  std::vector<EventFd*> event_fds;
  for (auto& group : groups_) {
    for (auto& selection : group) {
      for (auto& event_fd : selection.event_fds) {
        event_fds.push_back(event_fd.get());
      }
    }
  }
  return record_read_thread_->AddEventFds(event_fds);
}

bool EventSelectionSet::SyncKernelBuffer() {
  return record_read_thread_->SyncKernelBuffer();
}

// Read records from the RecordBuffer. If with_time_limit is false, read until the RecordBuffer is
// empty, otherwise stop after 100 ms or when the record buffer is empty.
bool EventSelectionSet::ReadMmapEventData(bool with_time_limit) {
  uint64_t start_time_in_ns;
  if (with_time_limit) {
    start_time_in_ns = GetSystemClock();
  }
  std::unique_ptr<Record> r;
  while ((r = record_read_thread_->GetRecord()) != nullptr) {
    if (!record_callback_(r.get())) {
      return false;
    }
    if (with_time_limit && (GetSystemClock() - start_time_in_ns) >= 1e8) {
      break;
    }
  }
  return true;
}

bool EventSelectionSet::FinishReadMmapEventData() {
  // Stop the read thread, so we don't get more records beyond current time.
  if (!SyncKernelBuffer() || !record_read_thread_->StopReadThread()) {
    return false;
  }
  if (!ReadMmapEventData(false)) {
    return false;
  }
  return true;
}

void EventSelectionSet::CloseEventFiles() {
  if (record_read_thread_) {
    record_read_thread_->StopReadThread();
  }
  for (auto& group : groups_) {
    for (auto& event : group) {
      event.event_fds.clear();
    }
  }
}

bool EventSelectionSet::StopWhenNoMoreTargets(double check_interval_in_sec) {
  return loop_->AddPeriodicEvent(SecondToTimeval(check_interval_in_sec),
                                 [&]() { return CheckMonitoredTargets(); });
}

bool EventSelectionSet::CheckMonitoredTargets() {
  if (!HasSampler()) {
    return loop_->ExitLoop();
  }
  for (const auto& tid : threads_) {
    if (IsThreadAlive(tid)) {
      return true;
    }
  }
  for (const auto& pid : processes_) {
    if (IsThreadAlive(pid)) {
      return true;
    }
  }
  return loop_->ExitLoop();
}

bool EventSelectionSet::HasSampler() {
  for (auto& group : groups_) {
    for (auto& sel : group) {
      if (!sel.event_fds.empty()) {
        return true;
      }
    }
  }
  return false;
}

bool EventSelectionSet::SetEnableEvents(bool enable) {
  for (auto& group : groups_) {
    for (auto& sel : group) {
      for (auto& fd : sel.event_fds) {
        if (!fd->SetEnableEvent(enable)) {
          return false;
        }
      }
    }
  }
  return true;
}

}  // namespace simpleperf
