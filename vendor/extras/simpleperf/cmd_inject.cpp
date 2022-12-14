/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include <unistd.h>

#include <memory>
#include <optional>
#include <regex>
#include <string>

#include <android-base/parseint.h>
#include <android-base/strings.h>

#include "ETMDecoder.h"
#include "cmd_inject_impl.h"
#include "command.h"
#include "record_file.h"
#include "system/extras/simpleperf/etm_branch_list.pb.h"
#include "thread_tree.h"
#include "utils.h"

namespace simpleperf {

std::string BranchToProtoString(const std::vector<bool>& branch) {
  size_t bytes = (branch.size() + 7) / 8;
  std::string res(bytes, '\0');
  for (size_t i = 0; i < branch.size(); i++) {
    if (branch[i]) {
      res[i >> 3] |= 1 << (i & 7);
    }
  }
  return res;
}

std::vector<bool> ProtoStringToBranch(const std::string& s, size_t bit_size) {
  std::vector<bool> branch(bit_size, false);
  for (size_t i = 0; i < bit_size; i++) {
    if (s[i >> 3] & (1 << (i & 7))) {
      branch[i] = true;
    }
  }
  return branch;
}

namespace {

constexpr const char* ETM_BRANCH_LIST_PROTO_MAGIC = "simpleperf:EtmBranchList";

using AddrPair = std::pair<uint64_t, uint64_t>;

struct AddrPairHash {
  size_t operator()(const AddrPair& ap) const noexcept {
    size_t seed = 0;
    HashCombine(seed, ap.first);
    HashCombine(seed, ap.second);
    return seed;
  }
};

enum class OutputFormat {
  AutoFDO,
  BranchList,
};

// When processing binary info in an input file, the binaries are identified by their path.
// But this isn't sufficient when merging binary info from multiple input files. Because
// binaries for the same path may be changed between generating input files. So after processing
// each input file, we create BinaryKeys to identify binaries, which consider path, build_id and
// kernel_start_addr (for vmlinux). kernel_start_addr affects how addresses in BranchListBinaryInfo
// are interpreted for vmlinux.
struct BinaryKey {
  std::string path;
  BuildId build_id;
  uint64_t kernel_start_addr = 0;

  BinaryKey() {}

  BinaryKey(const std::string& path, BuildId build_id) : path(path), build_id(build_id) {}

  BinaryKey(Dso* dso, uint64_t kernel_start_addr) : path(dso->Path()) {
    build_id = Dso::FindExpectedBuildIdForPath(dso->Path());
    if (dso->type() == DSO_KERNEL) {
      this->kernel_start_addr = kernel_start_addr;
    }
  }

  bool operator==(const BinaryKey& other) const {
    return path == other.path && build_id == other.build_id &&
           kernel_start_addr == other.kernel_start_addr;
  }
};

struct BinaryKeyHash {
  size_t operator()(const BinaryKey& key) const noexcept {
    size_t seed = 0;
    HashCombine(seed, key.path);
    HashCombine(seed, key.build_id);
    if (key.kernel_start_addr != 0) {
      HashCombine(seed, key.kernel_start_addr);
    }
    return seed;
  }
};

static void OverflowSafeAdd(uint64_t& dest, uint64_t add) {
  if (__builtin_add_overflow(dest, add, &dest)) {
    LOG(WARNING) << "Branch count overflow happened.";
    dest = UINT64_MAX;
  }
}

struct AutoFDOBinaryInfo {
  uint64_t first_load_segment_addr = 0;
  std::unordered_map<AddrPair, uint64_t, AddrPairHash> range_count_map;
  std::unordered_map<AddrPair, uint64_t, AddrPairHash> branch_count_map;

  void AddInstrRange(const ETMInstrRange& instr_range) {
    uint64_t total_count = instr_range.branch_taken_count;
    OverflowSafeAdd(total_count, instr_range.branch_not_taken_count);
    OverflowSafeAdd(range_count_map[AddrPair(instr_range.start_addr, instr_range.end_addr)],
                    total_count);
    if (instr_range.branch_taken_count > 0) {
      OverflowSafeAdd(branch_count_map[AddrPair(instr_range.end_addr, instr_range.branch_to_addr)],
                      instr_range.branch_taken_count);
    }
  }

  void Merge(const AutoFDOBinaryInfo& other) {
    for (const auto& p : other.range_count_map) {
      auto res = range_count_map.emplace(p.first, p.second);
      if (!res.second) {
        OverflowSafeAdd(res.first->second, p.second);
      }
    }
    for (const auto& p : other.branch_count_map) {
      auto res = branch_count_map.emplace(p.first, p.second);
      if (!res.second) {
        OverflowSafeAdd(res.first->second, p.second);
      }
    }
  }
};

using UnorderedBranchMap =
    std::unordered_map<uint64_t, std::unordered_map<std::vector<bool>, uint64_t>>;

struct BranchListBinaryInfo {
  DsoType dso_type;
  UnorderedBranchMap branch_map;

  void Merge(const BranchListBinaryInfo& other) {
    for (auto& other_p : other.branch_map) {
      auto it = branch_map.find(other_p.first);
      if (it == branch_map.end()) {
        branch_map[other_p.first] = std::move(other_p.second);
      } else {
        auto& map2 = it->second;
        for (auto& other_p2 : other_p.second) {
          auto it2 = map2.find(other_p2.first);
          if (it2 == map2.end()) {
            map2[other_p2.first] = other_p2.second;
          } else {
            OverflowSafeAdd(it2->second, other_p2.second);
          }
        }
      }
    }
  }

  BranchMap GetOrderedBranchMap() const {
    BranchMap result;
    for (const auto& p : branch_map) {
      uint64_t addr = p.first;
      const auto& b_map = p.second;
      result[addr] = std::map<std::vector<bool>, uint64_t>(b_map.begin(), b_map.end());
    }
    return result;
  }
};

using AutoFDOBinaryCallback = std::function<void(const BinaryKey&, AutoFDOBinaryInfo&)>;
using BranchListBinaryCallback = std::function<void(const BinaryKey&, BranchListBinaryInfo&)>;

class ThreadTreeWithFilter : public ThreadTree {
 public:
  void ExcludePid(pid_t pid) { exclude_pid_ = pid; }

  ThreadEntry* FindThread(int tid) const override {
    ThreadEntry* thread = ThreadTree::FindThread(tid);
    if (thread != nullptr && exclude_pid_ && thread->pid == exclude_pid_) {
      return nullptr;
    }
    return thread;
  }

 private:
  std::optional<pid_t> exclude_pid_;
};

class DsoFilter {
 public:
  DsoFilter(const std::regex& binary_name_regex) : binary_name_regex_(binary_name_regex) {}

  bool FilterDso(Dso* dso) {
    auto lookup = dso_filter_cache_.find(dso);
    if (lookup != dso_filter_cache_.end()) {
      return lookup->second;
    }
    bool match = std::regex_search(dso->Path(), binary_name_regex_);
    dso_filter_cache_.insert({dso, match});
    return match;
  }

 private:
  std::regex binary_name_regex_;
  std::unordered_map<Dso*, bool> dso_filter_cache_;
};

static uint64_t GetFirstLoadSegmentVaddr(Dso* dso) {
  ElfStatus status;
  if (auto elf = ElfFile::Open(dso->GetDebugFilePath(), &status); elf) {
    for (const auto& segment : elf->GetProgramHeader()) {
      if (segment.is_load) {
        return segment.vaddr;
      }
    }
  }
  return 0;
}

// Read perf.data, and generate AutoFDOBinaryInfo or BranchListBinaryInfo.
// To avoid resetting data, it only processes one input file per instance.
class PerfDataReader {
 public:
  PerfDataReader(const std::string& filename, bool exclude_perf, ETMDumpOption etm_dump_option,
                 const std::regex& binary_name_regex)
      : filename_(filename),
        exclude_perf_(exclude_perf),
        etm_dump_option_(etm_dump_option),
        dso_filter_(binary_name_regex) {}

  void SetCallback(const AutoFDOBinaryCallback& callback) { autofdo_callback_ = callback; }
  void SetCallback(const BranchListBinaryCallback& callback) { branch_list_callback_ = callback; }

  bool Read() {
    record_file_reader_ = RecordFileReader::CreateInstance(filename_);
    if (!record_file_reader_) {
      return false;
    }
    if (exclude_perf_) {
      const auto& info_map = record_file_reader_->GetMetaInfoFeature();
      if (auto it = info_map.find("recording_process"); it == info_map.end()) {
        LOG(ERROR) << filename_ << " doesn't support --exclude-perf";
        return false;
      } else {
        int pid;
        if (!android::base::ParseInt(it->second, &pid, 0)) {
          LOG(ERROR) << "invalid recording_process " << it->second << " in " << filename_;
          return false;
        }
        thread_tree_.ExcludePid(pid);
      }
    }
    record_file_reader_->LoadBuildIdAndFileFeatures(thread_tree_);
    if (!record_file_reader_->ReadDataSection([this](auto r) { return ProcessRecord(r.get()); })) {
      return false;
    }
    if (etm_decoder_ && !etm_decoder_->FinishData()) {
      return false;
    }
    if (autofdo_callback_) {
      ProcessAutoFDOBinaryInfo();
    } else if (branch_list_callback_) {
      ProcessBranchListBinaryInfo();
    }
    return true;
  }

 private:
  bool ProcessRecord(Record* r) {
    thread_tree_.Update(*r);
    if (r->type() == PERF_RECORD_AUXTRACE_INFO) {
      etm_decoder_ = ETMDecoder::Create(*static_cast<AuxTraceInfoRecord*>(r), thread_tree_);
      if (!etm_decoder_) {
        return false;
      }
      etm_decoder_->EnableDump(etm_dump_option_);
      if (autofdo_callback_) {
        etm_decoder_->RegisterCallback(
            [this](const ETMInstrRange& range) { ProcessInstrRange(range); });
      } else if (branch_list_callback_) {
        etm_decoder_->RegisterCallback(
            [this](const ETMBranchList& branch) { ProcessBranchList(branch); });
      }
    } else if (r->type() == PERF_RECORD_AUX) {
      AuxRecord* aux = static_cast<AuxRecord*>(r);
      uint64_t aux_size = aux->data->aux_size;
      if (aux_size > 0) {
        if (aux_data_buffer_.size() < aux_size) {
          aux_data_buffer_.resize(aux_size);
        }
        if (!record_file_reader_->ReadAuxData(aux->Cpu(), aux->data->aux_offset,
                                              aux_data_buffer_.data(), aux_size)) {
          LOG(ERROR) << "failed to read aux data in " << filename_;
          return false;
        }
        return etm_decoder_->ProcessData(aux_data_buffer_.data(), aux_size, !aux->Unformatted(),
                                         aux->Cpu());
      }
    } else if (r->type() == PERF_RECORD_MMAP && r->InKernel()) {
      auto& mmap_r = *static_cast<MmapRecord*>(r);
      if (android::base::StartsWith(mmap_r.filename, DEFAULT_KERNEL_MMAP_NAME)) {
        kernel_map_start_addr_ = mmap_r.data->addr;
      }
    }
    return true;
  }

  void ProcessInstrRange(const ETMInstrRange& instr_range) {
    if (!dso_filter_.FilterDso(instr_range.dso)) {
      return;
    }

    autofdo_binary_map_[instr_range.dso].AddInstrRange(instr_range);
  }

  void ProcessBranchList(const ETMBranchList& branch_list) {
    if (!dso_filter_.FilterDso(branch_list.dso)) {
      return;
    }

    auto& branch_map = branch_list_binary_map_[branch_list.dso].branch_map;
    ++branch_map[branch_list.addr][branch_list.branch];
  }

  void ProcessAutoFDOBinaryInfo() {
    for (auto& p : autofdo_binary_map_) {
      Dso* dso = p.first;
      AutoFDOBinaryInfo& binary = p.second;
      binary.first_load_segment_addr = GetFirstLoadSegmentVaddr(dso);
      autofdo_callback_(BinaryKey(dso, 0), binary);
    }
  }

  void ProcessBranchListBinaryInfo() {
    for (auto& p : branch_list_binary_map_) {
      Dso* dso = p.first;
      BranchListBinaryInfo& binary = p.second;
      binary.dso_type = dso->type();
      BinaryKey key(dso, 0);
      if (binary.dso_type == DSO_KERNEL) {
        if (kernel_map_start_addr_ == 0) {
          LOG(WARNING) << "Can't convert kernel ip addresses without kernel start addr. So remove "
                          "branches for the kernel.";
          continue;
        }
        if (dso->GetDebugFilePath() == dso->Path()) {
          // vmlinux isn't available. We still use kernel ip addr. Put kernel start addr in proto
          // for address conversion later.
          key.kernel_start_addr = kernel_map_start_addr_;
        }
      }
      branch_list_callback_(key, binary);
    }
  }

  const std::string filename_;
  bool exclude_perf_;
  ETMDumpOption etm_dump_option_;
  DsoFilter dso_filter_;
  AutoFDOBinaryCallback autofdo_callback_;
  BranchListBinaryCallback branch_list_callback_;

  std::vector<uint8_t> aux_data_buffer_;
  std::unique_ptr<ETMDecoder> etm_decoder_;
  std::unique_ptr<RecordFileReader> record_file_reader_;
  ThreadTreeWithFilter thread_tree_;
  uint64_t kernel_map_start_addr_ = 0;
  // Store results for AutoFDO.
  std::unordered_map<Dso*, AutoFDOBinaryInfo> autofdo_binary_map_;
  // Store results for BranchList.
  std::unordered_map<Dso*, BranchListBinaryInfo> branch_list_binary_map_;
};

// Read a protobuf file specified by etm_branch_list.proto, and generate BranchListBinaryInfo.
class BranchListReader {
 public:
  BranchListReader(const std::string& filename, const std::regex binary_name_regex)
      : filename_(filename), binary_name_regex_(binary_name_regex) {}

  void SetCallback(const BranchListBinaryCallback& callback) { callback_ = callback; }

  bool Read() {
    auto fd = FileHelper::OpenReadOnly(filename_);
    if (!fd.ok()) {
      PLOG(ERROR) << "failed to open " << filename_;
      return false;
    }

    proto::ETMBranchList branch_list_proto;
    if (!branch_list_proto.ParseFromFileDescriptor(fd)) {
      PLOG(ERROR) << "failed to read msg from " << filename_;
      return false;
    }
    if (branch_list_proto.magic() != ETM_BRANCH_LIST_PROTO_MAGIC) {
      PLOG(ERROR) << "file not in format etm_branch_list.proto: " << filename_;
      return false;
    }

    for (size_t i = 0; i < branch_list_proto.binaries_size(); i++) {
      const auto& binary_proto = branch_list_proto.binaries(i);
      if (!std::regex_search(binary_proto.path(), binary_name_regex_)) {
        continue;
      }
      BinaryKey key(binary_proto.path(), BuildId(binary_proto.build_id()));
      if (binary_proto.has_kernel_info()) {
        key.kernel_start_addr = binary_proto.kernel_info().kernel_start_addr();
      }
      BranchListBinaryInfo binary;
      auto dso_type = ToDsoType(binary_proto.type());
      if (!dso_type) {
        LOG(ERROR) << "invalid binary type in " << filename_;
        return false;
      }
      binary.dso_type = dso_type.value();
      binary.branch_map = BuildUnorderedBranchMap(binary_proto);
      callback_(key, binary);
    }
    return true;
  }

 private:
  std::optional<DsoType> ToDsoType(proto::ETMBranchList_Binary::BinaryType binary_type) {
    switch (binary_type) {
      case proto::ETMBranchList_Binary::ELF_FILE:
        return DSO_ELF_FILE;
      case proto::ETMBranchList_Binary::KERNEL:
        return DSO_KERNEL;
      case proto::ETMBranchList_Binary::KERNEL_MODULE:
        return DSO_KERNEL_MODULE;
      default:
        LOG(ERROR) << "unexpected binary type " << binary_type;
        return std::nullopt;
    }
  }

  UnorderedBranchMap BuildUnorderedBranchMap(const proto::ETMBranchList_Binary& binary_proto) {
    UnorderedBranchMap branch_map;
    for (size_t i = 0; i < binary_proto.addrs_size(); i++) {
      const auto& addr_proto = binary_proto.addrs(i);
      auto& b_map = branch_map[addr_proto.addr()];
      for (size_t j = 0; j < addr_proto.branches_size(); j++) {
        const auto& branch_proto = addr_proto.branches(j);
        std::vector<bool> branch =
            ProtoStringToBranch(branch_proto.branch(), branch_proto.branch_size());
        b_map[branch] = branch_proto.count();
      }
    }
    return branch_map;
  }

  const std::string filename_;
  const std::regex binary_name_regex_;
  BranchListBinaryCallback callback_;
};

// Convert BranchListBinaryInfo into AutoFDOBinaryInfo.
class BranchListToAutoFDOConverter {
 public:
  std::unique_ptr<AutoFDOBinaryInfo> Convert(const BinaryKey& key, BranchListBinaryInfo& binary) {
    BuildId build_id = key.build_id;
    std::unique_ptr<Dso> dso = Dso::CreateDsoWithBuildId(binary.dso_type, key.path, build_id);
    if (!dso || !CheckBuildId(dso.get(), key.build_id)) {
      return nullptr;
    }
    std::unique_ptr<AutoFDOBinaryInfo> autofdo_binary(new AutoFDOBinaryInfo);
    autofdo_binary->first_load_segment_addr = GetFirstLoadSegmentVaddr(dso.get());

    if (dso->type() == DSO_KERNEL) {
      ModifyBranchMapForKernel(dso.get(), key.kernel_start_addr, binary);
    }

    auto process_instr_range = [&](const ETMInstrRange& range) {
      CHECK_EQ(range.dso, dso.get());
      autofdo_binary->AddInstrRange(range);
    };

    auto result =
        ConvertBranchMapToInstrRanges(dso.get(), binary.GetOrderedBranchMap(), process_instr_range);
    if (!result.ok()) {
      LOG(WARNING) << "failed to build instr ranges for binary " << dso->Path() << ": "
                   << result.error();
      return nullptr;
    }
    return autofdo_binary;
  }

 private:
  bool CheckBuildId(Dso* dso, const BuildId& expected_build_id) {
    if (expected_build_id.IsEmpty()) {
      return true;
    }
    BuildId build_id;
    return GetBuildIdFromDsoPath(dso->GetDebugFilePath(), &build_id) &&
           build_id == expected_build_id;
  }

  void ModifyBranchMapForKernel(Dso* dso, uint64_t kernel_start_addr,
                                BranchListBinaryInfo& binary) {
    if (kernel_start_addr == 0) {
      // vmlinux has been provided when generating branch lists. Addresses in branch lists are
      // already vaddrs in vmlinux.
      return;
    }
    // Addresses are still kernel ip addrs in memory. Need to convert them to vaddrs in vmlinux.
    UnorderedBranchMap new_branch_map;
    for (auto& p : binary.branch_map) {
      uint64_t vaddr_in_file = dso->IpToVaddrInFile(p.first, kernel_start_addr, 0);
      new_branch_map[vaddr_in_file] = std::move(p.second);
    }
    binary.branch_map = std::move(new_branch_map);
  }
};

// Write instruction ranges to a file in AutoFDO text format.
class AutoFDOWriter {
 public:
  void AddAutoFDOBinary(const BinaryKey& key, AutoFDOBinaryInfo& binary) {
    auto it = binary_map_.find(key);
    if (it == binary_map_.end()) {
      binary_map_[key] = std::move(binary);
    } else {
      it->second.Merge(binary);
    }
  }

  bool Write(const std::string& output_filename) {
    std::unique_ptr<FILE, decltype(&fclose)> output_fp(fopen(output_filename.c_str(), "w"), fclose);
    if (!output_fp) {
      PLOG(ERROR) << "failed to write to " << output_filename;
      return false;
    }
    // autofdo_binary_map is used to store instruction ranges, which can have a large amount. And
    // it has a larger access time (instruction ranges * executed time). So it's better to use
    // unorder_maps to speed up access time. But we also want a stable output here, to compare
    // output changes result from code changes. So generate a sorted output here.
    std::vector<BinaryKey> keys;
    for (auto& p : binary_map_) {
      keys.emplace_back(p.first);
    }
    std::sort(keys.begin(), keys.end(),
              [](const BinaryKey& key1, const BinaryKey& key2) { return key1.path < key2.path; });
    if (keys.size() > 1) {
      fprintf(output_fp.get(),
              "// Please split this file. AutoFDO only accepts profile for one binary.\n");
    }
    for (const auto& key : keys) {
      const AutoFDOBinaryInfo& binary = binary_map_[key];
      // AutoFDO text format needs file_offsets instead of virtual addrs in a binary. And it uses
      // below formula: vaddr = file_offset + GetFirstLoadSegmentVaddr().
      uint64_t first_load_segment_addr = binary.first_load_segment_addr;

      auto to_offset = [&](uint64_t vaddr) -> uint64_t {
        if (vaddr == 0) {
          return 0;
        }
        CHECK_GE(vaddr, first_load_segment_addr);
        return vaddr - first_load_segment_addr;
      };

      // Write range_count_map.
      std::map<AddrPair, uint64_t> range_count_map(binary.range_count_map.begin(),
                                                   binary.range_count_map.end());
      fprintf(output_fp.get(), "%zu\n", range_count_map.size());
      for (const auto& pair2 : range_count_map) {
        const AddrPair& addr_range = pair2.first;
        uint64_t count = pair2.second;

        fprintf(output_fp.get(), "%" PRIx64 "-%" PRIx64 ":%" PRIu64 "\n",
                to_offset(addr_range.first), to_offset(addr_range.second), count);
      }

      // Write addr_count_map.
      fprintf(output_fp.get(), "0\n");

      // Write branch_count_map.
      std::map<AddrPair, uint64_t> branch_count_map(binary.branch_count_map.begin(),
                                                    binary.branch_count_map.end());
      fprintf(output_fp.get(), "%zu\n", branch_count_map.size());
      for (const auto& pair2 : branch_count_map) {
        const AddrPair& branch = pair2.first;
        uint64_t count = pair2.second;

        fprintf(output_fp.get(), "%" PRIx64 "->%" PRIx64 ":%" PRIu64 "\n", to_offset(branch.first),
                to_offset(branch.second), count);
      }

      // Write the binary path in comment.
      fprintf(output_fp.get(), "// %s\n\n", key.path.c_str());
    }
    return true;
  }

 private:
  std::unordered_map<BinaryKey, AutoFDOBinaryInfo, BinaryKeyHash> binary_map_;
};

// Merge BranchListBinaryInfo.
struct BranchListMerger {
  void AddBranchListBinary(const BinaryKey& key, BranchListBinaryInfo& binary) {
    auto it = binary_map.find(key);
    if (it == binary_map.end()) {
      binary_map[key] = std::move(binary);
    } else {
      it->second.Merge(binary);
    }
  }

  std::unordered_map<BinaryKey, BranchListBinaryInfo, BinaryKeyHash> binary_map;
};

// Write branch lists to a protobuf file specified by etm_branch_list.proto.
class BranchListWriter {
 public:
  bool Write(const std::string& output_filename,
             const std::unordered_map<BinaryKey, BranchListBinaryInfo, BinaryKeyHash>& binary_map) {
    // Don't produce empty output file.
    if (binary_map.empty()) {
      LOG(INFO) << "Skip empty output file.";
      unlink(output_filename.c_str());
      return true;
    }
    std::unique_ptr<FILE, decltype(&fclose)> output_fp(fopen(output_filename.c_str(), "wb"),
                                                       fclose);
    if (!output_fp) {
      PLOG(ERROR) << "failed to write to " << output_filename;
      return false;
    }

    proto::ETMBranchList branch_list_proto;
    branch_list_proto.set_magic(ETM_BRANCH_LIST_PROTO_MAGIC);
    std::vector<char> branch_buf;
    for (const auto& p : binary_map) {
      const BinaryKey& key = p.first;
      const BranchListBinaryInfo& binary = p.second;
      auto binary_proto = branch_list_proto.add_binaries();

      binary_proto->set_path(key.path);
      if (!key.build_id.IsEmpty()) {
        binary_proto->set_build_id(key.build_id.ToString().substr(2));
      }
      auto opt_binary_type = ToProtoBinaryType(binary.dso_type);
      if (!opt_binary_type.has_value()) {
        return false;
      }
      binary_proto->set_type(opt_binary_type.value());

      for (const auto& addr_p : binary.branch_map) {
        auto addr_proto = binary_proto->add_addrs();
        addr_proto->set_addr(addr_p.first);

        for (const auto& branch_p : addr_p.second) {
          const std::vector<bool>& branch = branch_p.first;
          auto branch_proto = addr_proto->add_branches();

          branch_proto->set_branch(BranchToProtoString(branch));
          branch_proto->set_branch_size(branch.size());
          branch_proto->set_count(branch_p.second);
        }
      }

      if (binary.dso_type == DSO_KERNEL) {
        binary_proto->mutable_kernel_info()->set_kernel_start_addr(key.kernel_start_addr);
      }
    }
    if (!branch_list_proto.SerializeToFileDescriptor(fileno(output_fp.get()))) {
      PLOG(ERROR) << "failed to write to " << output_filename;
      return false;
    }
    return true;
  }

 private:
  std::optional<proto::ETMBranchList_Binary::BinaryType> ToProtoBinaryType(DsoType dso_type) {
    switch (dso_type) {
      case DSO_ELF_FILE:
        return proto::ETMBranchList_Binary::ELF_FILE;
      case DSO_KERNEL:
        return proto::ETMBranchList_Binary::KERNEL;
      case DSO_KERNEL_MODULE:
        return proto::ETMBranchList_Binary::KERNEL_MODULE;
      default:
        LOG(ERROR) << "unexpected dso type " << dso_type;
        return std::nullopt;
    }
  }
};

class InjectCommand : public Command {
 public:
  InjectCommand()
      : Command("inject", "parse etm instruction tracing data",
                // clang-format off
"Usage: simpleperf inject [options]\n"
"--binary binary_name         Generate data only for binaries matching binary_name regex.\n"
"-i file1,file2,...           Input files. Default is perf.data. Support below formats:\n"
"                               1. perf.data generated by recording cs-etm event type.\n"
"                               2. branch_list file generated by `inject --output branch-list`.\n"
"                             If a file name starts with @, it contains a list of input files.\n"
"-o <file>                    output file. Default is perf_inject.data.\n"
"--output <format>            Select output file format:\n"
"                               autofdo      -- text format accepted by TextSampleReader\n"
"                                               of AutoFDO\n"
"                               branch-list  -- protobuf file in etm_branch_list.proto\n"
"                             Default is autofdo.\n"
"--dump-etm type1,type2,...   Dump etm data. A type is one of raw, packet and element.\n"
"--exclude-perf               Exclude trace data for the recording process.\n"
"--symdir <dir>               Look for binaries in a directory recursively.\n"
"\n"
"Examples:\n"
"1. Generate autofdo text output.\n"
"$ simpleperf inject -i perf.data -o autofdo.txt --output autofdo\n"
"\n"
"2. Generate branch list proto, then convert to autofdo text.\n"
"$ simpleperf inject -i perf.data -o branch_list.data --output branch-list\n"
"$ simpleperf inject -i branch_list.data -o autofdo.txt --output autofdo\n"
                // clang-format on
        ) {}

  bool Run(const std::vector<std::string>& args) override {
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    if (!ParseOptions(args)) {
      return false;
    }

    CHECK(!input_filenames_.empty());
    if (IsPerfDataFile(input_filenames_[0])) {
      switch (output_format_) {
        case OutputFormat::AutoFDO:
          return ConvertPerfDataToAutoFDO();
        case OutputFormat::BranchList:
          return ConvertPerfDataToBranchList();
      }
    } else {
      switch (output_format_) {
        case OutputFormat::AutoFDO:
          return ConvertBranchListToAutoFDO();
        case OutputFormat::BranchList:
          return ConvertBranchListToBranchList();
      }
    }
  }

 private:
  bool ParseOptions(const std::vector<std::string>& args) {
    const OptionFormatMap option_formats = {
        {"--binary", {OptionValueType::STRING, OptionType::SINGLE}},
        {"--dump-etm", {OptionValueType::STRING, OptionType::SINGLE}},
        {"--exclude-perf", {OptionValueType::NONE, OptionType::SINGLE}},
        {"-i", {OptionValueType::STRING, OptionType::MULTIPLE}},
        {"-o", {OptionValueType::STRING, OptionType::SINGLE}},
        {"--output", {OptionValueType::STRING, OptionType::SINGLE}},
        {"--symdir", {OptionValueType::STRING, OptionType::MULTIPLE}},
    };
    OptionValueMap options;
    std::vector<std::pair<OptionName, OptionValue>> ordered_options;
    if (!PreprocessOptions(args, option_formats, &options, &ordered_options, nullptr)) {
      return false;
    }

    if (auto value = options.PullValue("--binary"); value) {
      binary_name_regex_ = *value->str_value;
    }
    if (auto value = options.PullValue("--dump-etm"); value) {
      if (!ParseEtmDumpOption(*value->str_value, &etm_dump_option_)) {
        return false;
      }
    }
    exclude_perf_ = options.PullBoolValue("--exclude-perf");

    for (const OptionValue& value : options.PullValues("-i")) {
      std::vector<std::string> files = android::base::Split(*value.str_value, ",");
      for (std::string& file : files) {
        if (android::base::StartsWith(file, "@")) {
          if (!ReadFileList(file.substr(1), &input_filenames_)) {
            return false;
          }
        } else {
          input_filenames_.emplace_back(file);
        }
      }
    }
    if (input_filenames_.empty()) {
      input_filenames_.emplace_back("perf.data");
    }
    options.PullStringValue("-o", &output_filename_);
    if (auto value = options.PullValue("--output"); value) {
      const std::string& output = *value->str_value;
      if (output == "autofdo") {
        output_format_ = OutputFormat::AutoFDO;
      } else if (output == "branch-list") {
        output_format_ = OutputFormat::BranchList;
      } else {
        LOG(ERROR) << "unknown format in --output option: " << output;
        return false;
      }
    }
    if (auto value = options.PullValue("--symdir"); value) {
      if (!Dso::AddSymbolDir(*value->str_value)) {
        return false;
      }
      // Symbol dirs are cleaned when Dso count is decreased to zero, which can happen between
      // processing input files. To make symbol dirs always available, create a placeholder dso to
      // prevent cleaning from happening.
      placeholder_dso_ = Dso::CreateDso(DSO_UNKNOWN_FILE, "unknown");
    }
    CHECK(options.values.empty());
    return true;
  }

  bool ReadFileList(const std::string& path, std::vector<std::string>* file_list) {
    std::string data;
    if (!android::base::ReadFileToString(path, &data)) {
      PLOG(ERROR) << "failed to read " << path;
      return false;
    }
    std::vector<std::string> tokens = android::base::Tokenize(data, " \t\n\r");
    file_list->insert(file_list->end(), tokens.begin(), tokens.end());
    return true;
  }

  bool ConvertPerfDataToAutoFDO() {
    AutoFDOWriter autofdo_writer;
    auto callback = [&](const BinaryKey& key, AutoFDOBinaryInfo& binary) {
      autofdo_writer.AddAutoFDOBinary(key, binary);
    };
    for (const auto& input_filename : input_filenames_) {
      PerfDataReader reader(input_filename, exclude_perf_, etm_dump_option_, binary_name_regex_);
      reader.SetCallback(callback);
      if (!reader.Read()) {
        return false;
      }
    }
    return autofdo_writer.Write(output_filename_);
  }

  bool ConvertPerfDataToBranchList() {
    BranchListMerger branch_list_merger;
    auto callback = [&](const BinaryKey& key, BranchListBinaryInfo& binary) {
      branch_list_merger.AddBranchListBinary(key, binary);
    };
    for (const auto& input_filename : input_filenames_) {
      PerfDataReader reader(input_filename, exclude_perf_, etm_dump_option_, binary_name_regex_);
      reader.SetCallback(callback);
      if (!reader.Read()) {
        return false;
      }
    }
    BranchListWriter branch_list_writer;
    return branch_list_writer.Write(output_filename_, branch_list_merger.binary_map);
  }

  bool ConvertBranchListToAutoFDO() {
    // Step1 : Merge branch lists from all input files.
    BranchListMerger branch_list_merger;
    auto callback = [&](const BinaryKey& key, BranchListBinaryInfo& binary) {
      branch_list_merger.AddBranchListBinary(key, binary);
    };
    for (const auto& input_filename : input_filenames_) {
      BranchListReader reader(input_filename, binary_name_regex_);
      reader.SetCallback(callback);
      if (!reader.Read()) {
        return false;
      }
    }

    // Step2: Convert BranchListBinaryInfo to AutoFDOBinaryInfo.
    AutoFDOWriter autofdo_writer;
    BranchListToAutoFDOConverter converter;
    for (auto& p : branch_list_merger.binary_map) {
      const BinaryKey& key = p.first;
      BranchListBinaryInfo& binary = p.second;
      std::unique_ptr<AutoFDOBinaryInfo> autofdo_binary = converter.Convert(key, binary);
      if (autofdo_binary) {
        // Create new BinaryKey with kernel_start_addr = 0. Because AutoFDO output doesn't care
        // kernel_start_addr.
        autofdo_writer.AddAutoFDOBinary(BinaryKey(key.path, key.build_id), *autofdo_binary);
      }
    }

    // Step3: Write AutoFDOBinaryInfo.
    return autofdo_writer.Write(output_filename_);
  }

  bool ConvertBranchListToBranchList() {
    // Step1 : Merge branch lists from all input files.
    BranchListMerger branch_list_merger;
    auto callback = [&](const BinaryKey& key, BranchListBinaryInfo& binary) {
      branch_list_merger.AddBranchListBinary(key, binary);
    };
    for (const auto& input_filename : input_filenames_) {
      BranchListReader reader(input_filename, binary_name_regex_);
      reader.SetCallback(callback);
      if (!reader.Read()) {
        return false;
      }
    }
    // Step2: Write BranchListBinaryInfo.
    BranchListWriter branch_list_writer;
    return branch_list_writer.Write(output_filename_, branch_list_merger.binary_map);
  }

  std::regex binary_name_regex_{""};  // Default to match everything.
  bool exclude_perf_ = false;
  std::vector<std::string> input_filenames_;
  std::string output_filename_ = "perf_inject.data";
  OutputFormat output_format_ = OutputFormat::AutoFDO;
  ETMDumpOption etm_dump_option_;

  std::unique_ptr<Dso> placeholder_dso_;
};

}  // namespace

void RegisterInjectCommand() {
  return RegisterCommand("inject", [] { return std::unique_ptr<Command>(new InjectCommand); });
}

}  // namespace simpleperf
