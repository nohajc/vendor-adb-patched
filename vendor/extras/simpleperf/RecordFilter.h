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

#pragma once

#include <sys/types.h>

#include <optional>
#include <regex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "command.h"
#include "record.h"
#include "thread_tree.h"

namespace simpleperf {

#define RECORD_FILTER_OPTION_HELP_MSG                                                              \
  "--exclude-pid pid1,pid2,...   Exclude samples for selected processes.\n"                        \
  "--exclude-tid tid1,tid2,...   Exclude samples for selected threads.\n"                          \
  "--exclude-process-name process_name_regex   Exclude samples for processes with name\n"          \
  "                                            containing the regular expression.\n"               \
  "--exclude-thread-name thread_name_regex     Exclude samples for threads with name containing\n" \
  "                                            the regular expression.\n"                          \
  "--exclude-uid uid1,uid2,...   Exclude samples for processes belonging to selected uids.\n"      \
  "--include-pid pid1,pid2,...   Include samples for selected processes.\n"                        \
  "--include-tid tid1,tid2,...   Include samples for selected threads.\n"                          \
  "--include-process-name process_name_regex   Include samples for processes with name\n"          \
  "                                            containing the regular expression.\n"               \
  "--include-thread-name thread_name_regex     Include samples for threads with name containing\n" \
  "                                            the regular expression.\n"                          \
  "--include-uid uid1,uid2,...   Include samples for processes belonging to selected uids.\n"

struct RecordFilterCondition {
  bool used = false;
  std::set<pid_t> pids;
  std::set<pid_t> tids;
  std::vector<std::regex> process_name_regs;
  std::vector<std::regex> thread_name_regs;
  std::set<uid_t> uids;
};

// Filter SampleRecords based on the rule below:
//   out_sample_records = (in_sample_records & ~exclude_conditions) & include_conditions
//   By default, exclude_conditions = 0, include_conditions = 1.
class RecordFilter {
 public:
  RecordFilter(const ThreadTree& thread_tree) : thread_tree_(thread_tree) {}
  bool ParseOptions(OptionValueMap& options);
  void AddPids(const std::set<pid_t>& pids, bool exclude);
  void AddTids(const std::set<pid_t>& tids, bool exclude);
  void AddProcessNameRegex(const std::string& process_name, bool exclude);
  void AddThreadNameRegex(const std::string& thread_name, bool exclude);
  void AddUids(const std::set<uid_t>& uids, bool exclude);

  // Return true if the record passes filter.
  bool Check(const SampleRecord* r);

  RecordFilterCondition& GetCondition(bool exclude) {
    return exclude ? exclude_condition_ : include_condition_;
  }
  void Clear();

 private:
  bool CheckCondition(const SampleRecord* r, const RecordFilterCondition& condition);
  bool SearchInRegs(const std::string& s, const std::vector<std::regex>& regs);
  std::optional<uid_t> GetUidForProcess(pid_t pid);

  const ThreadTree& thread_tree_;
  RecordFilterCondition exclude_condition_;
  RecordFilterCondition include_condition_;
  std::unordered_map<pid_t, std::optional<uid_t>> pid_to_uid_map_;
};

inline const OptionFormatMap& GetRecordFilterOptionFormats() {
  static const OptionFormatMap option_formats = {
      {"--exclude-pid", {OptionValueType::STRING, OptionType::MULTIPLE, AppRunnerType::ALLOWED}},
      {"--exclude-tid", {OptionValueType::STRING, OptionType::MULTIPLE, AppRunnerType::ALLOWED}},
      {"--exclude-process-name",
       {OptionValueType::STRING, OptionType::MULTIPLE, AppRunnerType::ALLOWED}},
      {"--exclude-thread-name",
       {OptionValueType::STRING, OptionType::MULTIPLE, AppRunnerType::ALLOWED}},
      {"--exclude-uid", {OptionValueType::STRING, OptionType::MULTIPLE, AppRunnerType::ALLOWED}},
      {"--include-pid", {OptionValueType::STRING, OptionType::MULTIPLE, AppRunnerType::ALLOWED}},
      {"--include-tid", {OptionValueType::STRING, OptionType::MULTIPLE, AppRunnerType::ALLOWED}},
      {"--include-process-name",
       {OptionValueType::STRING, OptionType::MULTIPLE, AppRunnerType::ALLOWED}},
      {"--include-thread-name",
       {OptionValueType::STRING, OptionType::MULTIPLE, AppRunnerType::ALLOWED}},
      {"--include-uid", {OptionValueType::STRING, OptionType::MULTIPLE, AppRunnerType::ALLOWED}},
  };
  return option_formats;
}

}  // namespace simpleperf
