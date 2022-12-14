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

#include "report_utils.h"

#include <android-base/strings.h>

#include "JITDebugReader.h"
#include "utils.h"

namespace simpleperf {

static bool IsArtEntry(const CallChainReportEntry& entry, bool* is_jni_trampoline) {
  if (entry.execution_type == CallChainExecutionType::NATIVE_METHOD) {
    if (android::base::EndsWith(entry.dso->Path(), "/libart.so") ||
        android::base::EndsWith(entry.dso->Path(), "/libartd.so")) {
      *is_jni_trampoline = false;
      return true;
    }
    if (strcmp(entry.symbol->Name(), "art_jni_trampoline") == 0) {
      // art_jni_trampoline is a trampoline used to call jni methods in art runtime.
      // We want to hide it when hiding art frames.
      *is_jni_trampoline = true;
      return true;
    }
  }
  return false;
};

bool CallChainReportBuilder::AddProguardMappingFile(std::string_view mapping_file) {
  // The mapping file format is described in
  // https://www.guardsquare.com/en/products/proguard/manual/retrace.
  LineReader reader(mapping_file);
  if (!reader.Ok()) {
    PLOG(ERROR) << "failed to read " << mapping_file;
    return false;
  }
  ProguardMappingClass* cur_class = nullptr;
  std::string* line;
  while ((line = reader.ReadLine()) != nullptr) {
    std::string_view s = *line;
    if (s.empty() || s[0] == '#') {
      continue;
    }
    auto arrow_pos = s.find(" -> ");
    if (arrow_pos == s.npos) {
      continue;
    }
    auto arrow_end_pos = arrow_pos + strlen(" -> ");

    if (s[0] != ' ') {
      // Match line "original_classname -> obfuscated_classname:".
      if (auto colon_pos = s.find(':', arrow_end_pos); colon_pos != s.npos) {
        std::string_view original_classname = s.substr(0, arrow_pos);
        std::string obfuscated_classname(s.substr(arrow_end_pos, colon_pos - arrow_end_pos));
        cur_class = &proguard_class_map_[obfuscated_classname];
        cur_class->original_classname = original_classname;
      }
    } else if (cur_class != nullptr) {
      // Match line "... [original_classname.]original_methodname(...)... ->
      // obfuscated_methodname".
      if (auto left_brace_pos = s.rfind('(', arrow_pos); left_brace_pos != s.npos) {
        if (auto space_pos = s.rfind(' ', left_brace_pos); space_pos != s.npos) {
          auto original_methodname = s.substr(space_pos + 1, left_brace_pos - space_pos - 1);
          if (android::base::StartsWith(original_methodname, cur_class->original_classname)) {
            original_methodname.remove_prefix(cur_class->original_classname.size() + 1);
          }
          std::string obfuscated_methodname(s.substr(arrow_end_pos));
          cur_class->method_map[obfuscated_methodname] = original_methodname;
        }
      }
    }
  }
  return true;
}

std::vector<CallChainReportEntry> CallChainReportBuilder::Build(const ThreadEntry* thread,
                                                                const std::vector<uint64_t>& ips,
                                                                size_t kernel_ip_count) {
  std::vector<CallChainReportEntry> result;
  result.reserve(ips.size());
  for (size_t i = 0; i < ips.size(); i++) {
    const MapEntry* map = thread_tree_.FindMap(thread, ips[i], i < kernel_ip_count);
    Dso* dso = map->dso;
    uint64_t vaddr_in_file;
    const Symbol* symbol = thread_tree_.FindSymbol(map, ips[i], &vaddr_in_file, &dso);
    CallChainExecutionType execution_type = CallChainExecutionType::NATIVE_METHOD;
    if (dso->IsForJavaMethod()) {
      if (dso->type() == DSO_DEX_FILE) {
        execution_type = CallChainExecutionType::INTERPRETED_JVM_METHOD;
      } else {
        execution_type = CallChainExecutionType::JIT_JVM_METHOD;
      }
    }
    result.resize(result.size() + 1);
    auto& entry = result.back();
    entry.ip = ips[i];
    entry.symbol = symbol;
    entry.dso = dso;
    entry.vaddr_in_file = vaddr_in_file;
    entry.map = map;
    entry.execution_type = execution_type;
  }
  MarkArtFrame(result);
  if (remove_art_frame_) {
    auto it = std::remove_if(result.begin(), result.end(), [](const CallChainReportEntry& entry) {
      return entry.execution_type == CallChainExecutionType::ART_METHOD;
    });
    result.erase(it, result.end());
  }
  if (convert_jit_frame_) {
    ConvertJITFrame(result);
  }
  if (!proguard_class_map_.empty()) {
    DeObfuscateJavaMethods(result);
  }
  return result;
}

void CallChainReportBuilder::MarkArtFrame(std::vector<CallChainReportEntry>& callchain) {
  // Mark art methods before or after a JVM method.
  bool near_java_method = false;
  bool is_jni_trampoline = false;
  std::vector<size_t> jni_trampoline_positions;
  for (size_t i = 0; i < callchain.size(); ++i) {
    auto& entry = callchain[i];
    if (entry.execution_type == CallChainExecutionType::INTERPRETED_JVM_METHOD ||
        entry.execution_type == CallChainExecutionType::JIT_JVM_METHOD) {
      near_java_method = true;

      // Mark art frames before this entry.
      for (int j = static_cast<int>(i) - 1; j >= 0; j--) {
        if (!IsArtEntry(callchain[j], &is_jni_trampoline)) {
          break;
        }
        callchain[j].execution_type = CallChainExecutionType::ART_METHOD;
        if (is_jni_trampoline) {
          jni_trampoline_positions.push_back(j);
        }
      }
    } else if (near_java_method && IsArtEntry(entry, &is_jni_trampoline)) {
      entry.execution_type = CallChainExecutionType::ART_METHOD;
      if (is_jni_trampoline) {
        jni_trampoline_positions.push_back(i);
      }
    } else {
      near_java_method = false;
    }
  }
  // Functions called by art_jni_trampoline are jni methods. And we don't want to hide them.
  for (auto i : jni_trampoline_positions) {
    if (i > 0 && callchain[i - 1].execution_type == CallChainExecutionType::ART_METHOD) {
      callchain[i - 1].execution_type = CallChainExecutionType::NATIVE_METHOD;
    }
  }
}

void CallChainReportBuilder::ConvertJITFrame(std::vector<CallChainReportEntry>& callchain) {
  CollectJavaMethods();
  for (size_t i = 0; i < callchain.size();) {
    auto& entry = callchain[i];
    if (entry.dso->IsForJavaMethod() && entry.dso->type() == DSO_ELF_FILE) {
      // This is a JIT java method, merge it with the interpreted java method having the same
      // name if possible. Otherwise, merge it with other JIT java methods having the same name
      // by assigning a common dso_name.
      if (auto it = java_method_map_.find(entry.symbol->Name()); it != java_method_map_.end()) {
        entry.dso = it->second.dso;
        entry.symbol = it->second.symbol;
        // Not enough info to map an offset in a JIT method to an offset in a dex file. So just
        // use the symbol_addr.
        entry.vaddr_in_file = entry.symbol->addr;

        // ART may call from an interpreted Java method into its corresponding JIT method. To
        // avoid showing the method calling itself, remove the JIT frame.
        if (i + 1 < callchain.size() && callchain[i + 1].dso == entry.dso &&
            callchain[i + 1].symbol == entry.symbol) {
          callchain.erase(callchain.begin() + i);
          continue;
        }

      } else if (!JITDebugReader::IsPathInJITSymFile(entry.dso->Path())) {
        // Old JITSymFiles use names like "TemporaryFile-XXXXXX". So give them a better name.
        entry.dso_name = "[JIT cache]";
      }
    }
    i++;
  }
}

void CallChainReportBuilder::CollectJavaMethods() {
  if (!java_method_initialized_) {
    java_method_initialized_ = true;
    for (Dso* dso : thread_tree_.GetAllDsos()) {
      if (dso->type() == DSO_DEX_FILE) {
        dso->LoadSymbols();
        for (auto& symbol : dso->GetSymbols()) {
          java_method_map_.emplace(symbol.Name(), JavaMethod(dso, &symbol));
        }
      }
    }
  }
}

void CallChainReportBuilder::DeObfuscateJavaMethods(std::vector<CallChainReportEntry>& callchain) {
  for (auto& entry : callchain) {
    if (entry.execution_type != CallChainExecutionType::JIT_JVM_METHOD &&
        entry.execution_type != CallChainExecutionType::INTERPRETED_JVM_METHOD) {
      continue;
    }
    std::string_view name = entry.symbol->DemangledName();
    if (auto split_pos = name.rfind('.'); split_pos != name.npos) {
      std::string obfuscated_classname(name.substr(0, split_pos));
      if (auto it = proguard_class_map_.find(obfuscated_classname);
          it != proguard_class_map_.end()) {
        const ProguardMappingClass& proguard_class = it->second;
        std::string obfuscated_methodname(name.substr(split_pos + 1));
        if (auto method_it = proguard_class.method_map.find(obfuscated_methodname);
            method_it != proguard_class.method_map.end()) {
          std::string new_symbol_name = proguard_class.original_classname + "." + method_it->second;
          entry.symbol->SetDemangledName(new_symbol_name);
        }
      }
    }
  }
}

}  // namespace simpleperf
