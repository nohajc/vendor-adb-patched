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

#ifndef SIMPLE_PERF_COMMAND_H_
#define SIMPLE_PERF_COMMAND_H_

#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>

namespace simpleperf {

using OptionName = std::string;

enum class OptionType {
  SINGLE,    // this option has a single value (use the last one in the arg list)
  MULTIPLE,  // this option can have multiple values (keep all values appeared in the arg list)
  ORDERED,   // keep the order of this option in the arg list
};

enum class OptionValueType {
  NONE,  // No value is needed
  STRING,
  OPT_STRING,  // optional string
  UINT,
  DOUBLE,
};

// Whether an option is allowed to pass through simpleperf_app_runner.
enum class AppRunnerType {
  NOT_ALLOWED,
  ALLOWED,
  CHECK_FD,
  CHECK_PATH,
};

struct OptionFormat {
  OptionValueType value_type;
  OptionType type;
  AppRunnerType app_runner_type = AppRunnerType::NOT_ALLOWED;
};

using OptionFormatMap = std::unordered_map<OptionName, OptionFormat>;

union OptionValue {
  const std::string* str_value;
  uint64_t uint_value;
  double double_value;
};

struct OptionValueMap {
  std::multimap<OptionName, OptionValue> values;

  bool PullBoolValue(const OptionName& name) { return PullValue(name).has_value(); }

  template <typename T>
  bool PullUintValue(const OptionName& name, T* value, uint64_t min = 0,
                     uint64_t max = std::numeric_limits<T>::max()) {
    if (auto option_value = PullValue(name); option_value) {
      if (option_value->uint_value < min || option_value->uint_value > max) {
        LOG(ERROR) << "invalid " << name << ": " << option_value->uint_value;
        return false;
      }
      *value = option_value->uint_value;
    }
    return true;
  }

  bool PullDoubleValue(const OptionName& name, double* value,
                       double min = std::numeric_limits<double>::lowest(),
                       double max = std::numeric_limits<double>::max()) {
    if (auto option_value = PullValue(name); option_value) {
      if (option_value->double_value < min || option_value->double_value > max) {
        LOG(ERROR) << "invalid " << name << ": " << option_value->double_value;
        return false;
      }
      *value = option_value->double_value;
    }
    return true;
  }

  void PullStringValue(const OptionName& name, std::string* value) {
    if (auto option_value = PullValue(name); option_value) {
      CHECK(option_value->str_value != nullptr);
      *value = *option_value->str_value;
    }
  }

  std::optional<OptionValue> PullValue(const OptionName& name) {
    std::optional<OptionValue> res;
    if (auto it = values.find(name); it != values.end()) {
      res.emplace(it->second);
      values.erase(it);
    }
    return res;
  }

  std::vector<OptionValue> PullValues(const OptionName& name) {
    auto pair = values.equal_range(name);
    if (pair.first != pair.second) {
      std::vector<OptionValue> res;
      for (auto it = pair.first; it != pair.second; ++it) {
        res.emplace_back(it->second);
      }
      values.erase(name);
      return res;
    }
    return {};
  }
};

inline const OptionFormatMap& GetCommonOptionFormatMap() {
  static const OptionFormatMap option_formats = {
      {"-h", {OptionValueType::NONE, OptionType::SINGLE, AppRunnerType::ALLOWED}},
      {"--help", {OptionValueType::NONE, OptionType::SINGLE, AppRunnerType::ALLOWED}},
      {"--log", {OptionValueType::STRING, OptionType::SINGLE, AppRunnerType::ALLOWED}},
      {"--log-to-android-buffer",
       {OptionValueType::NONE, OptionType::SINGLE, AppRunnerType::ALLOWED}},
      {"--version", {OptionValueType::NONE, OptionType::SINGLE, AppRunnerType::ALLOWED}},
  };
  return option_formats;
}

class Command {
 public:
  Command(const std::string& name, const std::string& short_help_string,
          const std::string& long_help_string)
      : name_(name), short_help_string_(short_help_string), long_help_string_(long_help_string) {}

  virtual ~Command() {}

  const std::string& Name() const { return name_; }

  const std::string& ShortHelpString() const { return short_help_string_; }

  const std::string LongHelpString() const { return long_help_string_; }

  virtual bool Run(const std::vector<std::string>& args) = 0;

  bool PreprocessOptions(const std::vector<std::string>& args,
                         const OptionFormatMap& option_formats, OptionValueMap* options,
                         std::vector<std::pair<OptionName, OptionValue>>* ordered_options,
                         std::vector<std::string>* non_option_args = nullptr);

  template <typename T>
  bool GetUintOption(const std::vector<std::string>& args, size_t* pi, T* value, uint64_t min = 0,
                     uint64_t max = std::numeric_limits<T>::max(), bool allow_suffixes = false) {
    if (!NextArgumentOrError(args, pi)) {
      return false;
    }
    uint64_t tmp_value;
    if (!android::base::ParseUint(args[*pi], &tmp_value, max, allow_suffixes) || tmp_value < min) {
      LOG(ERROR) << "Invalid argument for option " << args[*pi - 1] << ": " << args[*pi];
      return false;
    }
    *value = static_cast<T>(tmp_value);
    return true;
  }

  bool GetDoubleOption(const std::vector<std::string>& args, size_t* pi, double* value,
                       double min = 0, double max = std::numeric_limits<double>::max());

 protected:
  bool NextArgumentOrError(const std::vector<std::string>& args, size_t* pi);
  void ReportUnknownOption(const std::vector<std::string>& args, size_t i);

 private:
  const std::string name_;
  const std::string short_help_string_;
  const std::string long_help_string_;

  DISALLOW_COPY_AND_ASSIGN(Command);
};

void RegisterCommand(const std::string& cmd_name,
                     const std::function<std::unique_ptr<Command>(void)>& callback);
void UnRegisterCommand(const std::string& cmd_name);
std::unique_ptr<Command> CreateCommandInstance(const std::string& cmd_name);
const std::vector<std::string> GetAllCommandNames();
bool RunSimpleperfCmd(int argc, char** argv);

extern bool log_to_android_buffer;

}  // namespace simpleperf

#endif  // SIMPLE_PERF_COMMAND_H_
