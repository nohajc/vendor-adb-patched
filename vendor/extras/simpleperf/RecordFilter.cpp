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

using android::base::Split;
using android::base::Trim;

namespace simpleperf {

namespace {

using TimeRange = std::pair<uint64_t, uint64_t>;

class TimeRanges {
 public:
  void Begin(uint64_t timestamp) {
    if (!begin_time_.has_value()) {
      begin_time_ = timestamp;
    }
  }

  bool End(uint64_t timestamp) {
    if (begin_time_.has_value()) {
      if (begin_time_ >= timestamp) {
        LOG(ERROR) << "Invalid time range in filter data: begin time " << begin_time_.value()
                   << " >= end time " << timestamp;
        return false;
      }
      ranges_.emplace_back(begin_time_.value(), timestamp);
      begin_time_.reset();
    }
    return true;
  }

  void NoMoreTimestamp() {
    if (begin_time_.has_value()) {
      ranges_.emplace_back(begin_time_.value(), UINT64_MAX);
    }
    std::sort(ranges_.begin(), ranges_.end());
  }

  bool Empty() const { return ranges_.empty(); }

  bool InRange(uint64_t timestamp) const {
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(),
                               std::pair<uint64_t, uint64_t>(timestamp, 0));
    if (it != ranges_.end() && it->first == timestamp) {
      return true;
    }
    if (it != ranges_.begin()) {
      --it;
      if (it->second > timestamp) {
        return true;
      }
    }
    return false;
  }

 private:
  std::optional<uint64_t> begin_time_;
  std::vector<TimeRange> ranges_;
};

}  // namespace

class TimeFilter {
 public:
  const std::string& GetClock() const { return clock_; }
  void SetClock(const std::string& clock) { clock_ = clock; }

  void GlobalBegin(uint64_t timestamp) { global_ranges_.Begin(timestamp); }

  bool GlobalEnd(uint64_t timestamp) { return global_ranges_.End(timestamp); }

  void ProcessBegin(pid_t pid, uint64_t timestamp) { process_ranges_[pid].Begin(timestamp); }

  bool ProcessEnd(pid_t pid, uint64_t timestamp) { return process_ranges_[pid].End(timestamp); }

  void ThreadBegin(pid_t tid, uint64_t timestamp) { thread_ranges_[tid].Begin(timestamp); }

  bool ThreadEnd(pid_t tid, uint64_t timestamp) { return thread_ranges_[tid].End(timestamp); }

  void NoMoreTimestamp() {
    global_ranges_.NoMoreTimestamp();
    for (auto& p : process_ranges_) {
      p.second.NoMoreTimestamp();
    }
    for (auto& p : thread_ranges_) {
      p.second.NoMoreTimestamp();
    }
  }

  bool Empty() const {
    return global_ranges_.Empty() && process_ranges_.empty() && thread_ranges_.empty();
  }

  bool Check(const SampleRecord& sample) const {
    uint64_t timestamp = sample.Timestamp();
    if (!global_ranges_.Empty() && !global_ranges_.InRange(timestamp)) {
      return false;
    }
    if (!process_ranges_.empty()) {
      auto it = process_ranges_.find(sample.tid_data.pid);
      if (it == process_ranges_.end() || !it->second.InRange(timestamp)) {
        return false;
      }
    }
    if (!thread_ranges_.empty()) {
      auto it = thread_ranges_.find(sample.tid_data.tid);
      if (it == thread_ranges_.end() || !it->second.InRange(timestamp)) {
        return false;
      }
    }
    return true;
  }

 private:
  std::string clock_ = "monotonic";
  TimeRanges global_ranges_;
  std::unordered_map<pid_t, TimeRanges> process_ranges_;
  std::unordered_map<pid_t, TimeRanges> thread_ranges_;
};

// Read filter file. The format is in doc/sample_filter.md.
class FilterFileReader {
 public:
  FilterFileReader(const std::string& filename) : filename_(filename) {}

  bool Read() {
    std::string data;
    if (!android::base::ReadFileToString(filename_, &data)) {
      PLOG(ERROR) << "failed to read " << filename_;
      return false;
    }
    line_number_ = 0;
    time_filter_.reset(new TimeFilter);
    std::string arg_str;
    std::vector<std::string> args;
    uint64_t timestamp;
    pid_t pid;
    for (const auto& line : Split(data, "\n")) {
      line_number_++;
      if (SearchCmd(line, "CLOCK", &arg_str)) {
        if (!SplitArgs(arg_str, 1, &args)) {
          return false;
        }
        time_filter_->SetClock(args[0]);
      } else if (SearchCmd(line, "GLOBAL_BEGIN", &arg_str)) {
        if (!SplitArgs(arg_str, 1, &args) || !ParseTimestamp(args[0], &timestamp)) {
          return false;
        }
        time_filter_->GlobalBegin(timestamp);
      } else if (SearchCmd(line, "GLOBAL_END", &arg_str)) {
        if (!SplitArgs(arg_str, 1, &args) || !ParseTimestamp(args[0], &timestamp) ||
            !time_filter_->GlobalEnd(timestamp)) {
          return false;
        }
      } else if (SearchCmd(line, "PROCESS_BEGIN", &arg_str)) {
        if (!SplitArgs(arg_str, 2, &args) || !ParsePid(args[0], &pid) ||
            !ParseTimestamp(args[1], &timestamp)) {
          return false;
        }
        time_filter_->ProcessBegin(pid, timestamp);
      } else if (SearchCmd(line, "PROCESS_END", &arg_str)) {
        if (!SplitArgs(arg_str, 2, &args) || !ParsePid(args[0], &pid) ||
            !ParseTimestamp(args[1], &timestamp) || !time_filter_->ProcessEnd(pid, timestamp)) {
          return false;
        }
      } else if (SearchCmd(line, "THREAD_BEGIN", &arg_str)) {
        if (!SplitArgs(arg_str, 2, &args) || !ParsePid(args[0], &pid) ||
            !ParseTimestamp(args[1], &timestamp)) {
          return false;
        }
        time_filter_->ThreadBegin(pid, timestamp);
      } else if (SearchCmd(line, "THREAD_END", &arg_str)) {
        if (!SplitArgs(arg_str, 2, &args) || !ParsePid(args[0], &pid) ||
            !ParseTimestamp(args[1], &timestamp) || !time_filter_->ThreadEnd(pid, timestamp)) {
          return false;
        }
      }
    }
    return true;
  }

  std::unique_ptr<TimeFilter>& GetTimeFilter() { return time_filter_; }

 private:
  bool SearchCmd(const std::string& s, const char* cmd, std::string* arg_str) {
    auto pos = s.find(cmd);
    if (pos == s.npos) {
      return false;
    }
    *arg_str = s.substr(pos + strlen(cmd));
    return true;
  }

  bool SplitArgs(const std::string& s, size_t nargs, std::vector<std::string>* args) {
    *args = Split(Trim(s), " ");
    if (args->size() != nargs) {
      LOG(ERROR) << "Invalid args in " << filename_ << ":" << line_number_ << ": " << s;
      return false;
    }
    return true;
  }

  bool ParsePid(const std::string& s, pid_t* pid) {
    if (!android::base::ParseInt(s.c_str(), pid, static_cast<pid_t>(0))) {
      LOG(ERROR) << "Invalid pid in " << filename_ << ":" << line_number_ << ": " << s;
      return false;
    }
    return true;
  }

  bool ParseTimestamp(const std::string& s, uint64_t* timestamp) {
    if (!android::base::ParseUint(s.c_str(), timestamp)) {
      LOG(ERROR) << "Invalid timestamp in " << filename_ << ":" << line_number_ << ": " << s;
      return false;
    }
    return true;
  }

  const std::string filename_;
  size_t line_number_ = 0;
  std::unique_ptr<TimeFilter> time_filter_;
};

RecordFilter::RecordFilter(const ThreadTree& thread_tree) : thread_tree_(thread_tree) {}

RecordFilter::~RecordFilter() {}

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
      if (auto uids = ParseUintVector<uint32_t>(*value.str_value); uids) {
        AddUids(uids.value(), exclude);
      } else {
        return false;
      }
    }
  }
  if (auto value = options.PullValue("--filter-file"); value) {
    if (!SetFilterFile(*value->str_value)) {
      return false;
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

void RecordFilter::AddUids(const std::set<uint32_t>& uids, bool exclude) {
  RecordFilterCondition& cond = GetCondition(exclude);
  cond.used = true;
  cond.uids.insert(uids.begin(), uids.end());
}

bool RecordFilter::SetFilterFile(const std::string& filename) {
  FilterFileReader reader(filename);
  if (!reader.Read()) {
    return false;
  }
  time_filter_ = std::move(reader.GetTimeFilter());
  return true;
}

bool RecordFilter::Check(const SampleRecord* r) {
  if (exclude_condition_.used && CheckCondition(r, exclude_condition_)) {
    return false;
  }
  if (include_condition_.used && !CheckCondition(r, include_condition_)) {
    return false;
  }
  if (time_filter_ && !time_filter_->Check(*r)) {
    return false;
  }
  return true;
}

bool RecordFilter::CheckClock(const std::string& clock) {
  if (time_filter_ && time_filter_->GetClock() != clock) {
    LOG(ERROR) << "clock generating sample timestamps is " << clock
               << ", which doesn't match clock used in time filter " << time_filter_->GetClock();
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

std::optional<uint32_t> RecordFilter::GetUidForProcess(pid_t pid) {
  if (auto it = pid_to_uid_map_.find(pid); it != pid_to_uid_map_.end()) {
    return it->second;
  }
  auto uid = GetProcessUid(pid);
  pid_to_uid_map_[pid] = uid;
  return uid;
}

}  // namespace simpleperf
