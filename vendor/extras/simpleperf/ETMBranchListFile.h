/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "ETMDecoder.h"
#include "RegEx.h"
#include "thread_tree.h"
#include "utils.h"

namespace simpleperf {

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

using BranchListBinaryMap = std::unordered_map<BinaryKey, BranchListBinaryInfo, BinaryKeyHash>;

bool BranchListBinaryMapToString(const BranchListBinaryMap& binary_map, std::string& s);
bool StringToBranchListBinaryMap(const std::string& s, BranchListBinaryMap& binary_map);

class BinaryFilter {
 public:
  BinaryFilter(const RegEx* binary_name_regex) : binary_name_regex_(binary_name_regex) {}

  void SetRegex(const RegEx* binary_name_regex) {
    binary_name_regex_ = binary_name_regex;
    dso_filter_cache_.clear();
  }

  bool Filter(Dso* dso) {
    auto lookup = dso_filter_cache_.find(dso);
    if (lookup != dso_filter_cache_.end()) {
      return lookup->second;
    }
    bool match = Filter(dso->Path());
    dso_filter_cache_.insert({dso, match});
    return match;
  }

  bool Filter(const std::string& path) {
    return binary_name_regex_ == nullptr || binary_name_regex_->Search(path);
  }

 private:
  const RegEx* binary_name_regex_;
  std::unordered_map<Dso*, bool> dso_filter_cache_;
};

// Convert ETM data into branch lists while recording.
class ETMBranchListGenerator {
 public:
  static std::unique_ptr<ETMBranchListGenerator> Create(bool dump_maps_from_proc);

  virtual ~ETMBranchListGenerator();
  virtual void SetExcludePid(pid_t pid) = 0;
  virtual void SetBinaryFilter(const RegEx* binary_name_regex) = 0;
  virtual bool ProcessRecord(const Record& r, bool& consumed) = 0;
  virtual BranchListBinaryMap GetBranchListBinaryMap() = 0;
};

// for testing
std::string BranchToProtoString(const std::vector<bool>& branch);
std::vector<bool> ProtoStringToBranch(const std::string& s, size_t bit_size);

}  // namespace simpleperf
