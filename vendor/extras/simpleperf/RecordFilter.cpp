/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "RecordFilter.h"

#include "environment.h"
#include "utils.h"

namespace simpleperf {

bool RecordFilter::ParseOptions(OptionValueMap& options) {
  for (bool exclude : {true, false}) {
    std::string prefix = exclude ? "--exclude-" : "--include-";
    for (const OptionValue& value : options.PullValues(prefix + "pid")) {
      if (auto pids = GetTidsFromString(*value.str_value, false); pids) {
        AddPids(pids.value(), exclude);
      } else {
        return false;
      }
    }
    for (const OptionValue& value : options.PullValues(prefix + "tid")) {
      if (auto tids = GetTidsFromString(*value.str_value, false); tids) {
        AddTids(tids.value(), exclude);
      } else {
        return false;
      }
    }
    for (const OptionValue& value : options.PullValues(prefix + "process-name")) {
      AddProcessNameRegex(*value.str_value, exclude);
    }
    for (const OptionValue& value : options.PullValues(prefix + "thread-name")) {
      AddThreadNameRegex(*value.str_value, exclude);
    }
    for (const OptionValue& value : options.PullValues(prefix + "uid")) {
      if (auto uids = ParseUintVector<uid_t>(*value.str_value); uids) {
        AddUids(uids.value(), exclude);
      } else {
        return false;
      }
    }
  }
  return true;
}

void RecordFilter::AddPids(const std::set<pid_t>& pids, bool exclude) {
  RecordFilterCondition& cond = GetCondition(exclude);
  cond.used = true;
  cond.pids.insert(pids.begin(), pids.end());
}

void RecordFilter::AddTids(const std::set<pid_t>& tids, bool exclude) {
  RecordFilterCondition& cond = GetCondition(exclude);
  cond.used = true;
  cond.tids.insert(tids.begin(), tids.end());
}

void RecordFilter::AddProcessNameRegex(const std::string& process_name, bool exclude) {
  RecordFilterCondition& cond = GetCondition(exclude);
  cond.used = true;
  cond.process_name_regs.emplace_back(process_name, std::regex::optimize);
}

void RecordFilter::AddThreadNameRegex(const std::string& thread_name, bool exclude) {
  RecordFilterCondition& cond = GetCondition(exclude);
  cond.used = true;
  cond.thread_name_regs.emplace_back(thread_name, std::regex::optimize);
}

void RecordFilter::AddUids(const std::set<uid_t>& uids, bool exclude) {
  RecordFilterCondition& cond = GetCondition(exclude);
  cond.used = true;
  cond.uids.insert(uids.begin(), uids.end());
}

bool RecordFilter::Check(const SampleRecord* r) {
  if (exclude_condition_.used && CheckCondition(r, exclude_condition_)) {
    return false;
  }
  if (include_condition_.used && !CheckCondition(r, include_condition_)) {
    return false;
  }
  return true;
}

void RecordFilter::Clear() {
  exclude_condition_ = RecordFilterCondition();
  include_condition_ = RecordFilterCondition();
  pid_to_uid_map_.clear();
}

bool RecordFilter::CheckCondition(const SampleRecord* r, const RecordFilterCondition& condition) {
  if (condition.pids.count(r->tid_data.pid) == 1) {
    return true;
  }
  if (condition.tids.count(r->tid_data.tid) == 1) {
    return true;
  }
  if (!condition.process_name_regs.empty()) {
    if (ThreadEntry* process = thread_tree_.FindThread(r->tid_data.pid); process != nullptr) {
      if (SearchInRegs(process->comm, condition.process_name_regs)) {
        return true;
      }
    }
  }
  if (!condition.thread_name_regs.empty()) {
    if (ThreadEntry* thread = thread_tree_.FindThread(r->tid_data.tid); thread != nullptr) {
      if (SearchInRegs(thread->comm, condition.thread_name_regs)) {
        return true;
      }
    }
  }
  if (!condition.uids.empty()) {
    if (auto uid_value = GetUidForProcess(r->tid_data.pid); uid_value) {
      if (condition.uids.count(uid_value.value()) == 1) {
        return true;
      }
    }
  }
  return false;
}

bool RecordFilter::SearchInRegs(const std::string& s, const std::vector<std::regex>& regs) {
  for (auto& reg : regs) {
    if (std::regex_search(s, reg)) {
      return true;
    }
  }
  return false;
}

std::optional<uid_t> RecordFilter::GetUidForProcess(pid_t pid) {
  if (auto it = pid_to_uid_map_.find(pid); it != pid_to_uid_map_.end()) {
    return it->second;
  }
  auto uid = GetProcessUid(pid);
  pid_to_uid_map_[pid] = uid;
  return uid;
}

}  // namespace simpleperf
