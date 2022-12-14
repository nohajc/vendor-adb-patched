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

#include <gtest/gtest.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <filesystem>
#include <map>
#include <memory>
#include <regex>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>

#include "ETMRecorder.h"
#include "ProbeEvents.h"
#include "cmd_record_impl.h"
#include "command.h"
#include "environment.h"
#include "event_selection_set.h"
#include "get_test_data.h"
#include "kallsyms.h"
#include "record.h"
#include "record_file.h"
#include "test_util.h"
#include "thread_tree.h"

using android::base::Realpath;
using android::base::StringPrintf;
using namespace simpleperf;
using namespace PerfFileFormat;
namespace fs = std::filesystem;

static std::unique_ptr<Command> RecordCmd() {
  return CreateCommandInstance("record");
}

static const char* GetDefaultEvent() {
  return HasHardwareCounter() ? "cpu-cycles" : "task-clock";
}

static bool RunRecordCmd(std::vector<std::string> v, const char* output_file = nullptr) {
  bool has_event = false;
  for (auto& arg : v) {
    if (arg == "-e" || arg == "--group") {
      has_event = true;
      break;
    }
  }
  if (!has_event) {
    v.insert(v.end(), {"-e", GetDefaultEvent()});
  }

  std::unique_ptr<TemporaryFile> tmpfile;
  std::string out_file;
  if (output_file != nullptr) {
    out_file = output_file;
  } else {
    tmpfile.reset(new TemporaryFile);
    out_file = tmpfile->path;
  }
  v.insert(v.end(), {"-o", out_file, "sleep", SLEEP_SEC});
  return RecordCmd()->Run(v);
}

TEST(record_cmd, no_options) {
  ASSERT_TRUE(RunRecordCmd({}));
}

TEST(record_cmd, system_wide_option) {
  TEST_IN_ROOT(ASSERT_TRUE(RunRecordCmd({"-a"})));
}

static void CheckEventType(const std::string& record_file, const std::string& event_type,
                           uint64_t sample_period, uint64_t sample_freq) {
  const EventType* type = FindEventTypeByName(event_type);
  ASSERT_TRUE(type != nullptr);
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(record_file);
  ASSERT_TRUE(reader);
  std::vector<EventAttrWithId> attrs = reader->AttrSection();
  for (auto& attr : attrs) {
    if (attr.attr->type == type->type && attr.attr->config == type->config) {
      if (attr.attr->freq == 0) {
        ASSERT_EQ(sample_period, attr.attr->sample_period);
        ASSERT_EQ(sample_freq, 0u);
      } else {
        ASSERT_EQ(sample_period, 0u);
        ASSERT_EQ(sample_freq, attr.attr->sample_freq);
      }
      return;
    }
  }
  FAIL();
}

TEST(record_cmd, sample_period_option) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({"-c", "100000"}, tmpfile.path));
  CheckEventType(tmpfile.path, GetDefaultEvent(), 100000u, 0);
}

TEST(record_cmd, event_option) {
  ASSERT_TRUE(RunRecordCmd({"-e", "cpu-clock"}));
}

TEST(record_cmd, freq_option) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({"-f", "99"}, tmpfile.path));
  CheckEventType(tmpfile.path, GetDefaultEvent(), 0, 99u);
  ASSERT_TRUE(RunRecordCmd({"-e", "cpu-clock", "-f", "99"}, tmpfile.path));
  CheckEventType(tmpfile.path, "cpu-clock", 0, 99u);
  ASSERT_FALSE(RunRecordCmd({"-f", std::to_string(UINT_MAX)}));
}

TEST(record_cmd, multiple_freq_or_sample_period_option) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({"-f", "99", "-e", "task-clock", "-c", "1000000", "-e", "cpu-clock"},
                           tmpfile.path));
  CheckEventType(tmpfile.path, "task-clock", 0, 99u);
  CheckEventType(tmpfile.path, "cpu-clock", 1000000u, 0u);
}

TEST(record_cmd, output_file_option) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RecordCmd()->Run({"-o", tmpfile.path, "-e", GetDefaultEvent(), "sleep", SLEEP_SEC}));
}

TEST(record_cmd, dump_kernel_mmap) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({}, tmpfile.path));
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader != nullptr);
  std::vector<std::unique_ptr<Record>> records = reader->DataSection();
  ASSERT_GT(records.size(), 0U);
  bool have_kernel_mmap = false;
  for (auto& record : records) {
    if (record->type() == PERF_RECORD_MMAP) {
      const MmapRecord* mmap_record = static_cast<const MmapRecord*>(record.get());
      if (android::base::StartsWith(mmap_record->filename, DEFAULT_KERNEL_MMAP_NAME)) {
        have_kernel_mmap = true;
        break;
      }
    }
  }
  ASSERT_TRUE(have_kernel_mmap);
}

TEST(record_cmd, dump_build_id_feature) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({}, tmpfile.path));
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader != nullptr);
  const FileHeader& file_header = reader->FileHeader();
  ASSERT_TRUE(file_header.features[FEAT_BUILD_ID / 8] & (1 << (FEAT_BUILD_ID % 8)));
  ASSERT_GT(reader->FeatureSectionDescriptors().size(), 0u);
}

TEST(record_cmd, tracepoint_event) {
  TEST_IN_ROOT(ASSERT_TRUE(RunRecordCmd({"-a", "-e", "sched:sched_switch"})));
}

TEST(record_cmd, rN_event) {
  TEST_REQUIRE_HW_COUNTER();
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  size_t event_number;
  if (GetBuildArch() == ARCH_ARM64 || GetBuildArch() == ARCH_ARM) {
    // As in D5.10.2 of the ARMv8 manual, ARM defines the event number space for PMU. part of the
    // space is for common event numbers (which will stay the same for all ARM chips), part of the
    // space is for implementation defined events. Here 0x08 is a common event for instructions.
    event_number = 0x08;
  } else if (GetBuildArch() == ARCH_X86_32 || GetBuildArch() == ARCH_X86_64) {
    // As in volume 3 chapter 19 of the Intel manual, 0x00c0 is the event number for instruction.
    event_number = 0x00c0;
  } else {
    GTEST_LOG_(INFO) << "Omit arch " << GetBuildArch();
    return;
  }
  std::string event_name = android::base::StringPrintf("r%zx", event_number);
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({"-e", event_name}, tmpfile.path));
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader);
  std::vector<EventAttrWithId> attrs = reader->AttrSection();
  ASSERT_EQ(1u, attrs.size());
  ASSERT_EQ(PERF_TYPE_RAW, attrs[0].attr->type);
  ASSERT_EQ(event_number, attrs[0].attr->config);
}

TEST(record_cmd, branch_sampling) {
  TEST_REQUIRE_HW_COUNTER();
  if (IsBranchSamplingSupported()) {
    ASSERT_TRUE(RunRecordCmd({"-b"}));
    ASSERT_TRUE(RunRecordCmd({"-j", "any,any_call,any_ret,ind_call"}));
    ASSERT_TRUE(RunRecordCmd({"-j", "any,k"}));
    ASSERT_TRUE(RunRecordCmd({"-j", "any,u"}));
    ASSERT_FALSE(RunRecordCmd({"-j", "u"}));
  } else {
    GTEST_LOG_(INFO) << "This test does nothing as branch stack sampling is "
                        "not supported on this device.";
  }
}

TEST(record_cmd, event_modifier) {
  ASSERT_TRUE(RunRecordCmd({"-e", GetDefaultEvent() + std::string(":u")}));
}

TEST(record_cmd, fp_callchain_sampling) {
  ASSERT_TRUE(RunRecordCmd({"--call-graph", "fp"}));
}

TEST(record_cmd, fp_callchain_sampling_warning_on_arm) {
  if (GetBuildArch() != ARCH_ARM) {
    GTEST_LOG_(INFO) << "This test does nothing as it only tests on arm arch.";
    return;
  }
  ASSERT_EXIT(
      {
        exit(RunRecordCmd({"--call-graph", "fp"}) ? 0 : 1);
      },
      testing::ExitedWithCode(0), "doesn't work well on arm");
}

TEST(record_cmd, system_wide_fp_callchain_sampling) {
  TEST_IN_ROOT(ASSERT_TRUE(RunRecordCmd({"-a", "--call-graph", "fp"})));
}

TEST(record_cmd, dwarf_callchain_sampling) {
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  ASSERT_TRUE(IsDwarfCallChainSamplingSupported());
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(1, &workloads);
  std::string pid = std::to_string(workloads[0]->GetPid());
  ASSERT_TRUE(RunRecordCmd({"-p", pid, "--call-graph", "dwarf"}));
  ASSERT_TRUE(RunRecordCmd({"-p", pid, "--call-graph", "dwarf,16384"}));
  ASSERT_FALSE(RunRecordCmd({"-p", pid, "--call-graph", "dwarf,65536"}));
  ASSERT_TRUE(RunRecordCmd({"-p", pid, "-g"}));
}

TEST(record_cmd, system_wide_dwarf_callchain_sampling) {
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  ASSERT_TRUE(IsDwarfCallChainSamplingSupported());
  TEST_IN_ROOT(RunRecordCmd({"-a", "--call-graph", "dwarf"}));
}

TEST(record_cmd, no_unwind_option) {
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  ASSERT_TRUE(IsDwarfCallChainSamplingSupported());
  ASSERT_TRUE(RunRecordCmd({"--call-graph", "dwarf", "--no-unwind"}));
  ASSERT_FALSE(RunRecordCmd({"--no-unwind"}));
}

TEST(record_cmd, post_unwind_option) {
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  ASSERT_TRUE(IsDwarfCallChainSamplingSupported());
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(1, &workloads);
  std::string pid = std::to_string(workloads[0]->GetPid());
  ASSERT_TRUE(RunRecordCmd({"-p", pid, "--call-graph", "dwarf", "--post-unwind"}));
  ASSERT_TRUE(RunRecordCmd({"-p", pid, "--call-graph", "dwarf", "--post-unwind=yes"}));
  ASSERT_TRUE(RunRecordCmd({"-p", pid, "--call-graph", "dwarf", "--post-unwind=no"}));
}

TEST(record_cmd, existing_processes) {
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(2, &workloads);
  std::string pid_list =
      android::base::StringPrintf("%d,%d", workloads[0]->GetPid(), workloads[1]->GetPid());
  ASSERT_TRUE(RunRecordCmd({"-p", pid_list}));
}

TEST(record_cmd, existing_threads) {
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(2, &workloads);
  // Process id can also be used as thread id in linux.
  std::string tid_list =
      android::base::StringPrintf("%d,%d", workloads[0]->GetPid(), workloads[1]->GetPid());
  ASSERT_TRUE(RunRecordCmd({"-t", tid_list}));
}

TEST(record_cmd, no_monitored_threads) {
  TemporaryFile tmpfile;
  ASSERT_FALSE(RecordCmd()->Run({"-o", tmpfile.path}));
  ASSERT_FALSE(RecordCmd()->Run({"-o", tmpfile.path, ""}));
}

TEST(record_cmd, more_than_one_event_types) {
  ASSERT_TRUE(RunRecordCmd({"-e", "task-clock,cpu-clock"}));
  ASSERT_TRUE(RunRecordCmd({"-e", "task-clock", "-e", "cpu-clock"}));
}

TEST(record_cmd, mmap_page_option) {
  ASSERT_TRUE(RunRecordCmd({"-m", "1"}));
  ASSERT_FALSE(RunRecordCmd({"-m", "0"}));
  ASSERT_FALSE(RunRecordCmd({"-m", "7"}));
}

static void CheckKernelSymbol(const std::string& path, bool need_kallsyms, bool* success) {
  *success = false;
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(path);
  ASSERT_TRUE(reader != nullptr);
  std::vector<std::unique_ptr<Record>> records = reader->DataSection();
  bool has_kernel_symbol_records = false;
  for (const auto& record : records) {
    if (record->type() == SIMPLE_PERF_RECORD_KERNEL_SYMBOL) {
      has_kernel_symbol_records = true;
    }
  }
  std::string kallsyms;
  bool require_kallsyms = need_kallsyms && LoadKernelSymbols(&kallsyms);
  ASSERT_EQ(require_kallsyms, has_kernel_symbol_records);
  *success = true;
}

TEST(record_cmd, kernel_symbol) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({"--no-dump-symbols"}, tmpfile.path));
  bool success;
  CheckKernelSymbol(tmpfile.path, true, &success);
  ASSERT_TRUE(success);
  ASSERT_TRUE(RunRecordCmd({"--no-dump-symbols", "--no-dump-kernel-symbols"}, tmpfile.path));
  CheckKernelSymbol(tmpfile.path, false, &success);
  ASSERT_TRUE(success);
}

static void ProcessSymbolsInPerfDataFile(
    const std::string& perf_data_file,
    const std::function<bool(const Symbol&, uint32_t)>& callback) {
  auto reader = RecordFileReader::CreateInstance(perf_data_file);
  ASSERT_TRUE(reader);
  FileFeature file;
  size_t read_pos = 0;
  while (reader->ReadFileFeature(read_pos, &file)) {
    for (const auto& symbol : file.symbols) {
      if (callback(symbol, file.type)) {
        return;
      }
    }
  }
}

// Check if dumped symbols in perf.data matches our expectation.
static bool CheckDumpedSymbols(const std::string& path, bool allow_dumped_symbols) {
  bool has_dumped_symbols = false;
  auto callback = [&](const Symbol&, uint32_t) {
    has_dumped_symbols = true;
    return true;
  };
  ProcessSymbolsInPerfDataFile(path, callback);
  // It is possible that there are no samples hitting functions having symbols.
  // So "allow_dumped_symbols = true" doesn't guarantee "has_dumped_symbols = true".
  if (!allow_dumped_symbols && has_dumped_symbols) {
    return false;
  }
  return true;
}

TEST(record_cmd, no_dump_symbols) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({}, tmpfile.path));
  ASSERT_TRUE(CheckDumpedSymbols(tmpfile.path, true));
  ASSERT_TRUE(RunRecordCmd({"--no-dump-symbols", "--no-dump-kernel-symbols"}, tmpfile.path));
  ASSERT_TRUE(CheckDumpedSymbols(tmpfile.path, false));
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  ASSERT_TRUE(IsDwarfCallChainSamplingSupported());
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(1, &workloads);
  std::string pid = std::to_string(workloads[0]->GetPid());
  ASSERT_TRUE(RunRecordCmd({"-p", pid, "-g"}, tmpfile.path));
  ASSERT_TRUE(CheckDumpedSymbols(tmpfile.path, true));
  ASSERT_TRUE(RunRecordCmd({"-p", pid, "-g", "--no-dump-symbols", "--no-dump-kernel-symbols"},
                           tmpfile.path));
  ASSERT_TRUE(CheckDumpedSymbols(tmpfile.path, false));
}

TEST(record_cmd, dump_kernel_symbols) {
  TEST_REQUIRE_ROOT();
  TemporaryFile tmpfile;
  ASSERT_TRUE(RecordCmd()->Run({"-a", "-o", tmpfile.path, "-e", GetDefaultEvent(), "sleep", "1"}));
  bool has_kernel_symbols = false;
  auto callback = [&](const Symbol&, uint32_t file_type) {
    if (file_type == DSO_KERNEL) {
      has_kernel_symbols = true;
    }
    return has_kernel_symbols;
  };
  ProcessSymbolsInPerfDataFile(tmpfile.path, callback);
  ASSERT_TRUE(has_kernel_symbols);
}

TEST(record_cmd, group_option) {
  ASSERT_TRUE(RunRecordCmd({"--group", "task-clock,cpu-clock", "-m", "16"}));
  ASSERT_TRUE(
      RunRecordCmd({"--group", "task-clock,cpu-clock", "--group", "task-clock:u,cpu-clock:u",
                    "--group", "task-clock:k,cpu-clock:k", "-m", "16"}));
}

TEST(record_cmd, symfs_option) {
  ASSERT_TRUE(RunRecordCmd({"--symfs", "/"}));
}

TEST(record_cmd, duration_option) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RecordCmd()->Run({"--duration", "1.2", "-p", std::to_string(getpid()), "-o",
                                tmpfile.path, "--in-app", "-e", GetDefaultEvent()}));
  ASSERT_TRUE(RecordCmd()->Run(
      {"--duration", "1", "-o", tmpfile.path, "-e", GetDefaultEvent(), "sleep", "2"}));
}

TEST(record_cmd, support_modifier_for_clock_events) {
  for (const std::string& e : {"cpu-clock", "task-clock"}) {
    for (const std::string& m : {"u", "k"}) {
      ASSERT_TRUE(RunRecordCmd({"-e", e + ":" + m})) << "event " << e << ":" << m;
    }
  }
}

TEST(record_cmd, handle_SIGHUP) {
  TemporaryFile tmpfile;
  int pipefd[2];
  ASSERT_EQ(0, pipe(pipefd));
  int read_fd = pipefd[0];
  int write_fd = pipefd[1];
  char data[8] = {};
  std::thread thread([&]() {
    android::base::ReadFully(read_fd, data, 7);
    kill(getpid(), SIGHUP);
  });
  ASSERT_TRUE(
      RecordCmd()->Run({"-o", tmpfile.path, "--start_profiling_fd", std::to_string(write_fd), "-e",
                        GetDefaultEvent(), "sleep", "1000000"}));
  thread.join();
  close(write_fd);
  close(read_fd);
  ASSERT_STREQ(data, "STARTED");
}

TEST(record_cmd, stop_when_no_more_targets) {
  TemporaryFile tmpfile;
  std::atomic<int> tid(0);
  std::thread thread([&]() {
    tid = gettid();
    sleep(1);
  });
  thread.detach();
  while (tid == 0)
    ;
  ASSERT_TRUE(RecordCmd()->Run(
      {"-o", tmpfile.path, "-t", std::to_string(tid), "--in-app", "-e", GetDefaultEvent()}));
}

TEST(record_cmd, donot_stop_when_having_targets) {
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(1, &workloads);
  std::string pid = std::to_string(workloads[0]->GetPid());
  uint64_t start_time_in_ns = GetSystemClock();
  TemporaryFile tmpfile;
  ASSERT_TRUE(RecordCmd()->Run(
      {"-o", tmpfile.path, "-p", pid, "--duration", "3", "-e", GetDefaultEvent()}));
  uint64_t end_time_in_ns = GetSystemClock();
  ASSERT_GT(end_time_in_ns - start_time_in_ns, static_cast<uint64_t>(2e9));
}

TEST(record_cmd, start_profiling_fd_option) {
  int pipefd[2];
  ASSERT_EQ(0, pipe(pipefd));
  int read_fd = pipefd[0];
  int write_fd = pipefd[1];
  ASSERT_EXIT(
      {
        close(read_fd);
        exit(RunRecordCmd({"--start_profiling_fd", std::to_string(write_fd)}) ? 0 : 1);
      },
      testing::ExitedWithCode(0), "");
  close(write_fd);
  std::string s;
  ASSERT_TRUE(android::base::ReadFdToString(read_fd, &s));
  close(read_fd);
  ASSERT_EQ("STARTED", s);
}

TEST(record_cmd, record_meta_info_feature) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({}, tmpfile.path));
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader);
  auto& info_map = reader->GetMetaInfoFeature();
  ASSERT_NE(info_map.find("simpleperf_version"), info_map.end());
  ASSERT_NE(info_map.find("timestamp"), info_map.end());
#if defined(__ANDROID__)
  ASSERT_NE(info_map.find("product_props"), info_map.end());
  ASSERT_NE(info_map.find("android_version"), info_map.end());
#endif
}

// See http://b/63135835.
TEST(record_cmd, cpu_clock_for_a_long_time) {
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(1, &workloads);
  std::string pid = std::to_string(workloads[0]->GetPid());
  TemporaryFile tmpfile;
  ASSERT_TRUE(
      RecordCmd()->Run({"-e", "cpu-clock", "-o", tmpfile.path, "-p", pid, "--duration", "3"}));
}

TEST(record_cmd, dump_regs_for_tracepoint_events) {
  TEST_REQUIRE_HOST_ROOT();
  TEST_REQUIRE_TRACEPOINT_EVENTS();
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  // Check if the kernel can dump registers for tracepoint events.
  // If not, probably a kernel patch below is missing:
  // "5b09a094f2 arm64: perf: Fix callchain parse error with kernel tracepoint events"
  ASSERT_TRUE(IsDumpingRegsForTracepointEventsSupported());
}

TEST(record_cmd, trace_offcpu_option) {
  // On linux host, we need root privilege to read tracepoint events.
  TEST_REQUIRE_HOST_ROOT();
  TEST_REQUIRE_TRACEPOINT_EVENTS();
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({"--trace-offcpu", "-f", "1000"}, tmpfile.path));
  CheckEventType(tmpfile.path, "sched:sched_switch", 1u, 0u);
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader);
  auto info_map = reader->GetMetaInfoFeature();
  ASSERT_EQ(info_map["trace_offcpu"], "true");
  // Release recording environment in perf.data, to avoid affecting tests below.
  reader.reset();

  // --trace-offcpu only works with cpu-clock, task-clock and cpu-cycles. cpu-cycles has been
  // tested above.
  ASSERT_TRUE(RunRecordCmd({"--trace-offcpu", "-e", "cpu-clock"}));
  ASSERT_TRUE(RunRecordCmd({"--trace-offcpu", "-e", "task-clock"}));
  ASSERT_FALSE(RunRecordCmd({"--trace-offcpu", "-e", "page-faults"}));
  // --trace-offcpu doesn't work with more than one event.
  ASSERT_FALSE(RunRecordCmd({"--trace-offcpu", "-e", "cpu-clock,task-clock"}));
}

TEST(record_cmd, exit_with_parent_option) {
  ASSERT_TRUE(RunRecordCmd({"--exit-with-parent"}));
}

TEST(record_cmd, clockid_option) {
  if (!IsSettingClockIdSupported()) {
    ASSERT_FALSE(RunRecordCmd({"--clockid", "monotonic"}));
  } else {
    TemporaryFile tmpfile;
    ASSERT_TRUE(RunRecordCmd({"--clockid", "monotonic"}, tmpfile.path));
    std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
    ASSERT_TRUE(reader);
    auto info_map = reader->GetMetaInfoFeature();
    ASSERT_EQ(info_map["clockid"], "monotonic");
  }
}

TEST(record_cmd, generate_samples_by_hw_counters) {
  TEST_REQUIRE_HW_COUNTER();
  std::vector<std::string> events = {"cpu-cycles", "instructions"};
  for (auto& event : events) {
    TemporaryFile tmpfile;
    ASSERT_TRUE(RecordCmd()->Run({"-e", event, "-o", tmpfile.path, "sleep", "1"}));
    std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
    ASSERT_TRUE(reader);
    bool has_sample = false;
    ASSERT_TRUE(reader->ReadDataSection([&](std::unique_ptr<Record> r) {
      if (r->type() == PERF_RECORD_SAMPLE) {
        has_sample = true;
      }
      return true;
    }));
    ASSERT_TRUE(has_sample);
  }
}

TEST(record_cmd, callchain_joiner_options) {
  ASSERT_TRUE(RunRecordCmd({"--no-callchain-joiner"}));
  ASSERT_TRUE(RunRecordCmd({"--callchain-joiner-min-matching-nodes", "2"}));
}

TEST(record_cmd, dashdash) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RecordCmd()->Run({"-o", tmpfile.path, "-e", GetDefaultEvent(), "--", "sleep", "1"}));
}

TEST(record_cmd, size_limit_option) {
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(1, &workloads);
  std::string pid = std::to_string(workloads[0]->GetPid());
  TemporaryFile tmpfile;
  ASSERT_TRUE(RecordCmd()->Run({"-o", tmpfile.path, "-p", pid, "--size-limit", "1k", "--duration",
                                "1", "-e", GetDefaultEvent()}));
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader);
  ASSERT_GT(reader->FileHeader().data.size, 1000u);
  ASSERT_LT(reader->FileHeader().data.size, 2000u);
  ASSERT_FALSE(RunRecordCmd({"--size-limit", "0"}));
}

TEST(record_cmd, support_mmap2) {
  // mmap2 is supported in kernel >= 3.16. If not supported, please cherry pick below kernel
  // patches:
  //   13d7a2410fa637 perf: Add attr->mmap2 attribute to an event
  //   f972eb63b1003f perf: Pass protection and flags bits through mmap2 interface.
  ASSERT_TRUE(IsMmap2Supported());
}

TEST(record_cmd, kernel_bug_making_zero_dyn_size) {
  // Test a kernel bug that makes zero dyn_size in kernel < 3.13. If it fails, please cherry pick
  // below kernel patch: 0a196848ca365e perf: Fix arch_perf_out_copy_user default
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(1, &workloads);
  std::string pid = std::to_string(workloads[0]->GetPid());
  TemporaryFile tmpfile;
  ASSERT_TRUE(RecordCmd()->Run({"-o", tmpfile.path, "-p", pid, "--call-graph", "dwarf,8",
                                "--no-unwind", "--duration", "1", "-e", GetDefaultEvent()}));
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader);
  bool has_sample = false;
  ASSERT_TRUE(reader->ReadDataSection([&](std::unique_ptr<Record> r) {
    if (r->type() == PERF_RECORD_SAMPLE && !r->InKernel()) {
      SampleRecord* sr = static_cast<SampleRecord*>(r.get());
      if (sr->stack_user_data.dyn_size == 0) {
        return false;
      }
      has_sample = true;
    }
    return true;
  }));
  ASSERT_TRUE(has_sample);
}

TEST(record_cmd, kernel_bug_making_zero_dyn_size_for_kernel_samples) {
  // Test a kernel bug that makes zero dyn_size for syscalls of 32-bit applications in 64-bit
  // kernels. If it fails, please cherry pick below kernel patch:
  // 02e184476eff8 perf/core: Force USER_DS when recording user stack data
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  TEST_REQUIRE_HOST_ROOT();
  TEST_REQUIRE_TRACEPOINT_EVENTS();
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(1, &workloads);
  std::string pid = std::to_string(workloads[0]->GetPid());
  TemporaryFile tmpfile;
  ASSERT_TRUE(RecordCmd()->Run({"-e", "sched:sched_switch", "-o", tmpfile.path, "-p", pid,
                                "--call-graph", "dwarf,8", "--no-unwind", "--duration", "1"}));
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader);
  bool has_sample = false;
  ASSERT_TRUE(reader->ReadDataSection([&](std::unique_ptr<Record> r) {
    if (r->type() == PERF_RECORD_SAMPLE && r->InKernel()) {
      SampleRecord* sr = static_cast<SampleRecord*>(r.get());
      if (sr->stack_user_data.dyn_size == 0) {
        return false;
      }
      has_sample = true;
    }
    return true;
  }));
  ASSERT_TRUE(has_sample);
}

TEST(record_cmd, cpu_percent_option) {
  ASSERT_TRUE(RunRecordCmd({"--cpu-percent", "50"}));
  ASSERT_FALSE(RunRecordCmd({"--cpu-percent", "0"}));
  ASSERT_FALSE(RunRecordCmd({"--cpu-percent", "101"}));
}

class RecordingAppHelper {
 public:
  bool InstallApk(const std::string& apk_path, const std::string& package_name) {
    return app_helper_.InstallApk(apk_path, package_name);
  }

  bool StartApp(const std::string& start_cmd) { return app_helper_.StartApp(start_cmd); }

  bool RecordData(const std::string& record_cmd) {
    std::vector<std::string> args = android::base::Split(record_cmd, " ");
    args.emplace_back("-o");
    args.emplace_back(perf_data_file_.path);
    return RecordCmd()->Run(args);
  }

  bool CheckData(const std::function<bool(const char*)>& process_symbol) {
    bool success = false;
    auto callback = [&](const Symbol& symbol, uint32_t) {
      if (process_symbol(symbol.DemangledName())) {
        success = true;
      }
      return success;
    };
    ProcessSymbolsInPerfDataFile(perf_data_file_.path, callback);
    return success;
  }

  std::string GetDataPath() const { return perf_data_file_.path; }

 private:
  AppHelper app_helper_;
  TemporaryFile perf_data_file_;
};

static void TestRecordingApps(const std::string& app_name, const std::string& app_type) {
  RecordingAppHelper helper;
  // Bring the app to foreground to avoid no samples.
  ASSERT_TRUE(helper.StartApp("am start " + app_name + "/.MainActivity"));

  ASSERT_TRUE(helper.RecordData("--app " + app_name + " -g --duration 10 -e " + GetDefaultEvent()));

  // Check if we can profile Java code by looking for a Java method name in dumped symbols, which
  // is app_name + ".MainActivity$1.run".
  const std::string expected_class_name = app_name + ".MainActivity";
  const std::string expected_method_name = "run";
  auto process_symbol = [&](const char* name) {
    return strstr(name, expected_class_name.c_str()) != nullptr &&
           strstr(name, expected_method_name.c_str()) != nullptr;
  };
  ASSERT_TRUE(helper.CheckData(process_symbol));

  // Check app_package_name and app_type.
  auto reader = RecordFileReader::CreateInstance(helper.GetDataPath());
  ASSERT_TRUE(reader);
  const std::unordered_map<std::string, std::string>& meta_info = reader->GetMetaInfoFeature();
  auto it = meta_info.find("app_package_name");
  ASSERT_NE(it, meta_info.end());
  ASSERT_EQ(it->second, app_name);
  it = meta_info.find("app_type");
  ASSERT_NE(it, meta_info.end());
  ASSERT_EQ(it->second, app_type);
}

TEST(record_cmd, app_option_for_debuggable_app) {
  TEST_REQUIRE_APPS();
  SetRunInAppToolForTesting(true, false);
  TestRecordingApps("com.android.simpleperf.debuggable", "debuggable");
  SetRunInAppToolForTesting(false, true);
  TestRecordingApps("com.android.simpleperf.debuggable", "debuggable");
}

TEST(record_cmd, app_option_for_profileable_app) {
  TEST_REQUIRE_APPS();
  SetRunInAppToolForTesting(false, true);
  TestRecordingApps("com.android.simpleperf.profileable", "profileable");
}

#if defined(__ANDROID__)
static void RecordJavaApp(RecordingAppHelper& helper) {
  // 1. Install apk.
  ASSERT_TRUE(helper.InstallApk(GetTestData("DisplayBitmaps.apk"),
                                "com.example.android.displayingbitmaps"));
  ASSERT_TRUE(helper.InstallApk(GetTestData("DisplayBitmapsTest.apk"),
                                "com.example.android.displayingbitmaps.test"));

  // 2. Start the app.
  ASSERT_TRUE(
      helper.StartApp("am instrument -w -r -e debug false -e class "
                      "com.example.android.displayingbitmaps.tests.GridViewTest "
                      "com.example.android.displayingbitmaps.test/"
                      "androidx.test.runner.AndroidJUnitRunner"));

  // 3. Record perf.data.
  SetRunInAppToolForTesting(true, true);
  ASSERT_TRUE(helper.RecordData(
      "-e cpu-clock --app com.example.android.displayingbitmaps -g --duration 15"));
}
#endif  // defined(__ANDROID__)

TEST(record_cmd, record_java_app) {
#if defined(__ANDROID__)
  RecordingAppHelper helper;

  RecordJavaApp(helper);
  if (HasFailure()) {
    return;
  }

  // Check perf.data by looking for java symbols.
  auto process_symbol = [&](const char* name) {
#if !defined(IN_CTS_TEST)
    const char* expected_name_with_keyguard = "androidx.test.runner";  // when screen is locked
    if (strstr(name, expected_name_with_keyguard) != nullptr) {
      return true;
    }
#endif
    const char* expected_name = "androidx.test.espresso";  // when screen stays awake
    return strstr(name, expected_name) != nullptr;
  };
  ASSERT_TRUE(helper.CheckData(process_symbol));
#else
  GTEST_LOG_(INFO) << "This test tests a function only available on Android.";
#endif
}

TEST(record_cmd, record_native_app) {
#if defined(__ANDROID__)
  // In case of non-native ABI guest symbols are never directly executed, thus
  // don't appear in perf.data. Instead binary translator executes code
  // translated from guest at runtime.
  OMIT_TEST_ON_NON_NATIVE_ABIS();

  RecordingAppHelper helper;
  // 1. Install apk.
  ASSERT_TRUE(helper.InstallApk(GetTestData("EndlessTunnel.apk"), "com.google.sample.tunnel"));

  // 2. Start the app.
  ASSERT_TRUE(
      helper.StartApp("am start -n com.google.sample.tunnel/android.app.NativeActivity -a "
                      "android.intent.action.MAIN -c android.intent.category.LAUNCHER"));

  // 3. Record perf.data.
  SetRunInAppToolForTesting(true, true);
  ASSERT_TRUE(helper.RecordData("-e cpu-clock --app com.google.sample.tunnel -g --duration 10"));

  // 4. Check perf.data.
  auto process_symbol = [&](const char* name) {
    const char* expected_name_with_keyguard = "NativeActivity";  // when screen is locked
    if (strstr(name, expected_name_with_keyguard) != nullptr) {
      return true;
    }
    const char* expected_name = "PlayScene::DoFrame";  // when screen is awake
    return strstr(name, expected_name) != nullptr;
  };
  ASSERT_TRUE(helper.CheckData(process_symbol));
#else
  GTEST_LOG_(INFO) << "This test tests a function only available on Android.";
#endif
}

TEST(record_cmd, check_trampoline_after_art_jni_methods) {
  // Test if art jni methods are called by art_jni_trampoline.
#if defined(__ANDROID__)
  RecordingAppHelper helper;

  RecordJavaApp(helper);
  if (HasFailure()) {
    return;
  }

  // Check if art::Method_invoke() is called by art_jni_trampoline.
  auto reader = RecordFileReader::CreateInstance(helper.GetDataPath());
  ASSERT_TRUE(reader);
  ThreadTree thread_tree;

  auto get_symbol_name = [&](ThreadEntry* thread, uint64_t ip) -> std::string {
    const MapEntry* map = thread_tree.FindMap(thread, ip, false);
    const Symbol* symbol = thread_tree.FindSymbol(map, ip, nullptr, nullptr);
    return symbol->DemangledName();
  };

  bool has_check = false;

  auto process_record = [&](std::unique_ptr<Record> r) {
    thread_tree.Update(*r);
    if (r->type() == PERF_RECORD_SAMPLE) {
      auto sample = static_cast<SampleRecord*>(r.get());
      ThreadEntry* thread = thread_tree.FindThreadOrNew(sample->tid_data.pid, sample->tid_data.tid);
      size_t kernel_ip_count;
      std::vector<uint64_t> ips = sample->GetCallChain(&kernel_ip_count);
      for (size_t i = kernel_ip_count; i < ips.size(); i++) {
        std::string sym_name = get_symbol_name(thread, ips[i]);
        if (android::base::StartsWith(sym_name, "art::Method_invoke") && i + 1 < ips.size()) {
          has_check = true;
          if (get_symbol_name(thread, ips[i + 1]) != "art_jni_trampoline") {
            return false;
          }
        }
      }
    }
    return true;
  };
  ASSERT_TRUE(reader->ReadDataSection(process_record));
  ASSERT_TRUE(has_check);
#else
  GTEST_LOG_(INFO) << "This test tests a function only available on Android.";
#endif
}

TEST(record_cmd, no_cut_samples_option) {
  ASSERT_TRUE(RunRecordCmd({"--no-cut-samples"}));
}

TEST(record_cmd, cs_etm_event) {
  if (!ETMRecorder::GetInstance().CheckEtmSupport()) {
    GTEST_LOG_(INFO) << "Omit this test since etm isn't supported on this device";
    return;
  }
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm"}, tmpfile.path));
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader);

  // cs-etm uses sample period instead of sample freq.
  ASSERT_EQ(reader->AttrSection().size(), 1u);
  const perf_event_attr* attr = reader->AttrSection()[0].attr;
  ASSERT_EQ(attr->freq, 0);
  ASSERT_EQ(attr->sample_period, 1);

  bool has_auxtrace_info = false;
  bool has_auxtrace = false;
  bool has_aux = false;
  ASSERT_TRUE(reader->ReadDataSection([&](std::unique_ptr<Record> r) {
    if (r->type() == PERF_RECORD_AUXTRACE_INFO) {
      has_auxtrace_info = true;
    } else if (r->type() == PERF_RECORD_AUXTRACE) {
      has_auxtrace = true;
    } else if (r->type() == PERF_RECORD_AUX) {
      has_aux = true;
    }
    return true;
  }));
  ASSERT_TRUE(has_auxtrace_info);
  ASSERT_TRUE(has_auxtrace);
  ASSERT_TRUE(has_aux);
}

TEST(record_cmd, cs_etm_system_wide) {
  TEST_REQUIRE_ROOT();
  if (!ETMRecorder::GetInstance().CheckEtmSupport()) {
    GTEST_LOG_(INFO) << "Omit this test since etm isn't supported on this device";
    return;
  }
  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm", "-a"}));
}

TEST(record_cmd, aux_buffer_size_option) {
  if (!ETMRecorder::GetInstance().CheckEtmSupport()) {
    GTEST_LOG_(INFO) << "Omit this test since etm isn't supported on this device";
    return;
  }
  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm", "--aux-buffer-size", "1m"}));
  // not page size aligned
  ASSERT_FALSE(RunRecordCmd({"-e", "cs-etm", "--aux-buffer-size", "1024"}));
  // not power of two
  ASSERT_FALSE(RunRecordCmd({"-e", "cs-etm", "--aux-buffer-size", "12k"}));
}

TEST(record_cmd, addr_filter_option) {
  TEST_REQUIRE_HW_COUNTER();
  if (!ETMRecorder::GetInstance().CheckEtmSupport()) {
    GTEST_LOG_(INFO) << "Omit this test since etm isn't supported on this device";
    return;
  }
  FILE* fp = popen("which sleep", "r");
  ASSERT_TRUE(fp != nullptr);
  std::string path;
  ASSERT_TRUE(android::base::ReadFdToString(fileno(fp), &path));
  pclose(fp);
  path = android::base::Trim(path);
  std::string sleep_exec_path;
  ASSERT_TRUE(Realpath(path, &sleep_exec_path));
  // --addr-filter doesn't apply to cpu-cycles.
  ASSERT_FALSE(RunRecordCmd({"--addr-filter", "filter " + sleep_exec_path}));
  TemporaryFile record_file;
  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm", "--addr-filter", "filter " + sleep_exec_path},
                           record_file.path));
  TemporaryFile inject_file;
  ASSERT_TRUE(
      CreateCommandInstance("inject")->Run({"-i", record_file.path, "-o", inject_file.path}));
  std::string data;
  ASSERT_TRUE(android::base::ReadFileToString(inject_file.path, &data));
  // Only instructions in sleep_exec_path are traced.
  for (auto& line : android::base::Split(data, "\n")) {
    if (android::base::StartsWith(line, "dso ")) {
      std::string dso = line.substr(strlen("dso "), sleep_exec_path.size());
      ASSERT_EQ(dso, sleep_exec_path);
    }
  }

  // Test if different filter types are accepted by the kernel.
  auto elf = ElfFile::Open(sleep_exec_path);
  uint64_t off;
  uint64_t addr = elf->ReadMinExecutableVaddr(&off);
  // file start
  std::string filter = StringPrintf("start 0x%" PRIx64 "@%s", addr, sleep_exec_path.c_str());
  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm", "--addr-filter", filter}));
  // file stop
  filter = StringPrintf("stop 0x%" PRIx64 "@%s", addr, sleep_exec_path.c_str());
  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm", "--addr-filter", filter}));
  // file range
  filter = StringPrintf("filter 0x%" PRIx64 "-0x%" PRIx64 "@%s", addr, addr + 4,
                        sleep_exec_path.c_str());
  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm", "--addr-filter", filter}));
  // If kernel panic, try backporting "perf/core: Fix crash when using HW tracing kernel
  // filters".
  // kernel start
  uint64_t fake_kernel_addr = (1ULL << 63);
  filter = StringPrintf("start 0x%" PRIx64, fake_kernel_addr);
  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm", "--addr-filter", filter}));
  // kernel stop
  filter = StringPrintf("stop 0x%" PRIx64, fake_kernel_addr);
  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm", "--addr-filter", filter}));
  // kernel range
  filter = StringPrintf("filter 0x%" PRIx64 "-0x%" PRIx64, fake_kernel_addr, fake_kernel_addr + 4);
  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm", "--addr-filter", filter}));
}

TEST(record_cmd, pmu_event_option) {
  TEST_REQUIRE_PMU_COUNTER();
  TEST_REQUIRE_HW_COUNTER();
  std::string event_string;
  if (GetBuildArch() == ARCH_X86_64) {
    event_string = "cpu/cpu-cycles/";
  } else if (GetBuildArch() == ARCH_ARM64) {
    event_string = "armv8_pmuv3/cpu_cycles/";
  } else {
    GTEST_LOG_(INFO) << "Omit arch " << GetBuildArch();
    return;
  }
  TEST_IN_ROOT(ASSERT_TRUE(RunRecordCmd({"-e", event_string})));
}

TEST(record_cmd, exclude_perf_option) {
  ASSERT_TRUE(RunRecordCmd({"--exclude-perf"}));
  if (IsRoot()) {
    TemporaryFile tmpfile;
    ASSERT_TRUE(RecordCmd()->Run(
        {"-a", "--exclude-perf", "--duration", "1", "-e", GetDefaultEvent(), "-o", tmpfile.path}));
    std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(tmpfile.path);
    ASSERT_TRUE(reader);
    pid_t perf_pid = getpid();
    ASSERT_TRUE(reader->ReadDataSection([&](std::unique_ptr<Record> r) {
      if (r->type() == PERF_RECORD_SAMPLE) {
        if (static_cast<SampleRecord*>(r.get())->tid_data.pid == perf_pid) {
          return false;
        }
      }
      return true;
    }));
  }
}

TEST(record_cmd, tp_filter_option) {
  TEST_REQUIRE_HOST_ROOT();
  TEST_REQUIRE_TRACEPOINT_EVENTS();
  // Test string operands both with quotes and without quotes.
  for (const auto& filter :
       std::vector<std::string>({"prev_comm != 'sleep'", "prev_comm != sleep"})) {
    TemporaryFile tmpfile;
    ASSERT_TRUE(RunRecordCmd({"-e", "sched:sched_switch", "--tp-filter", filter}, tmpfile.path))
        << filter;
    CaptureStdout capture;
    ASSERT_TRUE(capture.Start());
    ASSERT_TRUE(CreateCommandInstance("dump")->Run({tmpfile.path}));
    std::string data = capture.Finish();
    // Check that samples with prev_comm == sleep are filtered out. Although we do the check all the
    // time, it only makes sense when running as root. Tracepoint event fields are not allowed
    // to record unless running as root.
    ASSERT_EQ(data.find("prev_comm: sleep"), std::string::npos) << filter;
  }
}

TEST(record_cmd, ParseAddrFilterOption) {
  auto option_to_str = [](const std::string& option) {
    auto filters = ParseAddrFilterOption(option);
    std::string s;
    for (auto& filter : filters) {
      if (!s.empty()) {
        s += ',';
      }
      s += filter.ToString();
    }
    return s;
  };
  std::string path;
  ASSERT_TRUE(Realpath(GetTestData(ELF_FILE), &path));

  // Test file filters.
  ASSERT_EQ(option_to_str("filter " + path), "filter 0x0/0x73c@" + path);
  ASSERT_EQ(option_to_str("filter 0x400502-0x400527@" + path), "filter 0x502/0x25@" + path);
  ASSERT_EQ(option_to_str("start 0x400502@" + path + ",stop 0x400527@" + path),
            "start 0x502@" + path + ",stop 0x527@" + path);

  // Test '-' in file path. Create a temporary file with '-' in name.
  TemporaryDir tmpdir;
  fs::path tmpfile = fs::path(tmpdir.path) / "elf-with-hyphen";
  ASSERT_TRUE(fs::copy_file(path, tmpfile));
  ASSERT_EQ(option_to_str("filter " + tmpfile.string()), "filter 0x0/0x73c@" + tmpfile.string());

  // Test kernel filters.
  ASSERT_EQ(option_to_str("filter 0x12345678-0x1234567a"), "filter 0x12345678/0x2");
  ASSERT_EQ(option_to_str("start 0x12345678,stop 0x1234567a"), "start 0x12345678,stop 0x1234567a");
}

TEST(record_cmd, kprobe_option) {
  TEST_REQUIRE_ROOT();
  ProbeEvents probe_events;
  if (!probe_events.IsKprobeSupported()) {
    GTEST_LOG_(INFO) << "Skip this test as kprobe isn't supported by the kernel.";
    return;
  }
  ASSERT_TRUE(RunRecordCmd({"-e", "kprobes:myprobe", "--kprobe", "p:myprobe do_sys_open"}));
  // A default kprobe event is created if not given an explicit --kprobe option.
  ASSERT_TRUE(RunRecordCmd({"-e", "kprobes:do_sys_open"}));
  ASSERT_TRUE(RunRecordCmd({"--group", "kprobes:do_sys_open"}));
}

TEST(record_cmd, record_filter_options) {
  ASSERT_TRUE(
      RunRecordCmd({"--exclude-pid", "1,2", "--exclude-tid", "3,4", "--exclude-process-name",
                    "processA", "--exclude-thread-name", "threadA", "--exclude-uid", "5,6"}));
  ASSERT_TRUE(
      RunRecordCmd({"--include-pid", "1,2", "--include-tid", "3,4", "--include-process-name",
                    "processB", "--include-thread-name", "threadB", "--include-uid", "5,6"}));
}

TEST(record_cmd, keep_failed_unwinding_result_option) {
  OMIT_TEST_ON_NON_NATIVE_ABIS();
  std::vector<std::unique_ptr<Workload>> workloads;
  CreateProcesses(1, &workloads);
  std::string pid = std::to_string(workloads[0]->GetPid());
  ASSERT_TRUE(RunRecordCmd(
      {"-p", pid, "-g", "--keep-failed-unwinding-result", "--keep-failed-unwinding-debug-info"}));
}

TEST(record_cmd, kernel_address_warning) {
  TEST_REQUIRE_NON_ROOT();
  const std::string warning_msg = "Access to kernel symbol addresses is restricted.";
  CapturedStderr capture;

  // When excluding kernel samples, no kernel address warning is printed.
  ResetKernelAddressWarning();
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({"-e", "cpu-clock:u"}, tmpfile.path));
  capture.Stop();
  ASSERT_EQ(capture.str().find(warning_msg), std::string::npos);

  // When not excluding kernel samples, kernel address warning is printed once.
  capture.Reset();
  capture.Start();
  ResetKernelAddressWarning();
  ASSERT_TRUE(RunRecordCmd({"-e", "cpu-clock"}, tmpfile.path));
  capture.Stop();
  std::string output = capture.str();
  auto pos = output.find(warning_msg);
  ASSERT_NE(pos, std::string::npos);
  ASSERT_EQ(output.find(warning_msg, pos + warning_msg.size()), std::string::npos);
}

TEST(record_cmd, add_meta_info_option) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({"--add-meta-info", "key1=value1", "--add-meta-info", "key2=value2"},
                           tmpfile.path));
  auto reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader);

  const std::unordered_map<std::string, std::string>& meta_info = reader->GetMetaInfoFeature();
  auto it = meta_info.find("key1");
  ASSERT_NE(it, meta_info.end());
  ASSERT_EQ(it->second, "value1");
  it = meta_info.find("key2");
  ASSERT_NE(it, meta_info.end());
  ASSERT_EQ(it->second, "value2");

  // Report error for invalid meta info.
  ASSERT_FALSE(RunRecordCmd({"--add-meta-info", "key1"}, tmpfile.path));
  ASSERT_FALSE(RunRecordCmd({"--add-meta-info", "key1="}, tmpfile.path));
  ASSERT_FALSE(RunRecordCmd({"--add-meta-info", "=value1"}, tmpfile.path));
}

TEST(record_cmd, device_meta_info) {
  TemporaryFile tmpfile;
  ASSERT_TRUE(RunRecordCmd({}, tmpfile.path));
  auto reader = RecordFileReader::CreateInstance(tmpfile.path);
  ASSERT_TRUE(reader);

  const std::unordered_map<std::string, std::string>& meta_info = reader->GetMetaInfoFeature();
  auto it = meta_info.find("android_sdk_version");
  ASSERT_NE(it, meta_info.end());
  ASSERT_FALSE(it->second.empty());
  it = meta_info.find("android_build_type");
  ASSERT_NE(it, meta_info.end());
  ASSERT_FALSE(it->second.empty());
}
