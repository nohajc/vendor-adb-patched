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

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "record_file.h"
#include "report_utils.h"
#include "thread_tree.h"

using namespace simpleperf;

class CallChainReportBuilderTest : public testing::Test {
 protected:
  virtual void SetUp() {
    // To test different options for CallChainReportBuilder, we create a fake thread, add fake
    // libraries used by the thread, and provide fake symbols in each library. We need four
    // types of libraries: native, interpreter, jit cache and dex file.
    thread_tree.SetThreadName(1, 1, "thread1");
    thread = thread_tree.FindThread(1);

    // Add symbol info for the native library.
    FileFeature file;
    file.path = fake_native_lib_path;
    file.type = DSO_ELF_FILE;
    file.min_vaddr = file.file_offset_of_min_vaddr = 0;
    file.symbols = {
        Symbol("native_func1", 0x0, 0x100),
        Symbol("art_jni_trampoline", 0x100, 0x100),
    };
    thread_tree.AddDsoInfo(file);

    // Add symbol info for the interpreter library.
    file.path = fake_interpreter_path;
    file.type = DSO_ELF_FILE;
    file.min_vaddr = file.file_offset_of_min_vaddr = 0;
    file.symbols = {
        Symbol("art_func1", 0x0, 0x100),
        Symbol("art_func2", 0x100, 0x100),
        Symbol("_ZN3artL13Method_invokeEP7_JNIEnvP8_jobjectS3_P13_jobjectArray", 0x200, 0x100),
    };
    thread_tree.AddDsoInfo(file);

    // Add symbol info for the dex file.
    file.path = fake_dex_file_path;
    file.type = DSO_DEX_FILE;
    file.min_vaddr = file.file_offset_of_min_vaddr = 0;
    file.symbols = {
        Symbol("java_method1", 0x0, 0x100),
        Symbol("java_method2", 0x100, 0x100),
        Symbol("obfuscated_class.obfuscated_java_method", 0x200, 0x100),
    };
    thread_tree.AddDsoInfo(file);

    // Add symbol info for the jit cache.
    file.path = fake_jit_cache_path;
    file.type = DSO_ELF_FILE;
    file.min_vaddr = file.file_offset_of_min_vaddr = 0;
    file.symbols = {
        Symbol("java_method2", 0x3000, 0x100),
        Symbol("java_method3", 0x3100, 0x100),
        Symbol("obfuscated_class.obfuscated_java_method2", 0x3200, 0x100),
    };
    thread_tree.AddDsoInfo(file);

    // Add map layout for libraries used in the thread:
    // 0x0000 - 0x1000 is mapped to the native library.
    // 0x1000 - 0x2000 is mapped to the interpreter library.
    // 0x2000 - 0x3000 is mapped to the dex file.
    // 0x3000 - 0x4000 is mapped to the jit cache.
    thread_tree.AddThreadMap(1, 1, 0x0, 0x1000, 0x0, fake_native_lib_path);
    thread_tree.AddThreadMap(1, 1, 0x1000, 0x1000, 0x0, fake_interpreter_path);
    thread_tree.AddThreadMap(1, 1, 0x2000, 0x1000, 0x0, fake_dex_file_path);
    thread_tree.AddThreadMap(1, 1, 0x3000, 0x1000, 0x0, fake_jit_cache_path,
                             map_flags::PROT_JIT_SYMFILE_MAP);
  }

  ThreadTree thread_tree;
  const ThreadEntry* thread;
  const std::string fake_native_lib_path = "fake_dir/fake_native_lib.so";
  const std::string fake_interpreter_path = "fake_dir/libart.so";
  const std::string fake_dex_file_path = "fake_dir/framework.jar";
  const std::string fake_jit_cache_path = "fake_jit_app_cache:0";

  const std::vector<uint64_t> fake_ips = {
      0x1000,  // art_func1
      0x1100,  // art_func2
      0x2000,  // java_method1 in dex file
      0x1000,  // art_func1
      0x1100,  // art_func2
      0x3000,  // java_method2 in jit cache
      0x1000,  // art_func1
      0x1100,  // art_func2
  };
};

TEST_F(CallChainReportBuilderTest, default_option) {
  // Test default option: remove_art_frame = true, convert_jit_frame = true.
  // The callchain shouldn't include interpreter frames. And the JIT frame is
  // converted to a dex frame.
  CallChainReportBuilder builder(thread_tree);
  std::vector<CallChainReportEntry> entries = builder.Build(thread, fake_ips, 0);
  ASSERT_EQ(entries.size(), 2);
  ASSERT_EQ(entries[0].ip, 0x2000);
  ASSERT_STREQ(entries[0].symbol->Name(), "java_method1");
  ASSERT_EQ(entries[0].dso->Path(), fake_dex_file_path);
  ASSERT_EQ(entries[0].vaddr_in_file, 0);
  ASSERT_EQ(entries[0].execution_type, CallChainExecutionType::INTERPRETED_JVM_METHOD);
  ASSERT_EQ(entries[1].ip, 0x3000);
  ASSERT_STREQ(entries[1].symbol->Name(), "java_method2");
  ASSERT_EQ(entries[1].dso->Path(), fake_dex_file_path);
  ASSERT_EQ(entries[1].vaddr_in_file, 0x100);
  ASSERT_EQ(entries[1].execution_type, CallChainExecutionType::JIT_JVM_METHOD);
}

TEST_F(CallChainReportBuilderTest, not_convert_jit_frame) {
  // Test option: remove_art_frame = true, convert_jit_frame = false.
  // The callchain shouldn't include interpreter frames. And the JIT frame isn't
  // converted to a dex frame.
  CallChainReportBuilder builder(thread_tree);
  builder.SetConvertJITFrame(false);
  std::vector<CallChainReportEntry> entries = builder.Build(thread, fake_ips, 0);
  ASSERT_EQ(entries.size(), 2);
  ASSERT_EQ(entries[0].ip, 0x2000);
  ASSERT_STREQ(entries[0].symbol->Name(), "java_method1");
  ASSERT_EQ(entries[0].dso->Path(), fake_dex_file_path);
  ASSERT_EQ(entries[0].vaddr_in_file, 0);
  ASSERT_EQ(entries[0].execution_type, CallChainExecutionType::INTERPRETED_JVM_METHOD);
  ASSERT_EQ(entries[1].ip, 0x3000);
  ASSERT_STREQ(entries[1].symbol->Name(), "java_method2");
  ASSERT_EQ(entries[1].dso->Path(), fake_jit_cache_path);
  ASSERT_EQ(entries[1].vaddr_in_file, 0x3000);
  ASSERT_EQ(entries[1].execution_type, CallChainExecutionType::JIT_JVM_METHOD);
}

TEST_F(CallChainReportBuilderTest, not_remove_art_frame) {
  // Test option: remove_art_frame = false, convert_jit_frame = true.
  // The callchain should include interpreter frames. And the JIT frame is
  // converted to a dex frame.
  CallChainReportBuilder builder(thread_tree);
  builder.SetRemoveArtFrame(false);
  std::vector<CallChainReportEntry> entries = builder.Build(thread, fake_ips, 0);
  ASSERT_EQ(entries.size(), 8);
  for (size_t i : {0, 3, 6}) {
    ASSERT_EQ(entries[i].ip, 0x1000);
    ASSERT_STREQ(entries[i].symbol->Name(), "art_func1");
    ASSERT_EQ(entries[i].dso->Path(), fake_interpreter_path);
    ASSERT_EQ(entries[i].vaddr_in_file, 0);
    ASSERT_EQ(entries[i].execution_type, CallChainExecutionType::ART_METHOD);
    ASSERT_EQ(entries[i + 1].ip, 0x1100);
    ASSERT_STREQ(entries[i + 1].symbol->Name(), "art_func2");
    ASSERT_EQ(entries[i + 1].dso->Path(), fake_interpreter_path);
    ASSERT_EQ(entries[i + 1].vaddr_in_file, 0x100);
    ASSERT_EQ(entries[i + 1].execution_type, CallChainExecutionType::ART_METHOD);
  }
  ASSERT_EQ(entries[2].ip, 0x2000);
  ASSERT_STREQ(entries[2].symbol->Name(), "java_method1");
  ASSERT_EQ(entries[2].dso->Path(), fake_dex_file_path);
  ASSERT_EQ(entries[2].vaddr_in_file, 0);
  ASSERT_EQ(entries[2].execution_type, CallChainExecutionType::INTERPRETED_JVM_METHOD);
  ASSERT_EQ(entries[5].ip, 0x3000);
  ASSERT_STREQ(entries[5].symbol->Name(), "java_method2");
  ASSERT_EQ(entries[5].dso->Path(), fake_dex_file_path);
  ASSERT_EQ(entries[5].vaddr_in_file, 0x100);
  ASSERT_EQ(entries[5].execution_type, CallChainExecutionType::JIT_JVM_METHOD);
}

TEST_F(CallChainReportBuilderTest, remove_jit_frame_called_by_dex_frame) {
  // Test option: remove_art_frame = true, convert_jit_frame = true.
  // The callchain should remove the JIT frame called by a dex frame having the same symbol name.
  std::vector<uint64_t> fake_ips = {
      0x3000,  // java_method2 in jit cache
      0x1000,  // art_func1
      0x1100,  // art_func2
      0x2100,  // java_method2 in dex file
      0x1000,  // art_func1
  };
  CallChainReportBuilder builder(thread_tree);
  std::vector<CallChainReportEntry> entries = builder.Build(thread, fake_ips, 0);
  ASSERT_EQ(entries.size(), 1);
  ASSERT_EQ(entries[0].ip, 0x2100);
  ASSERT_STREQ(entries[0].symbol->Name(), "java_method2");
  ASSERT_EQ(entries[0].dso->Path(), fake_dex_file_path);
  ASSERT_EQ(entries[0].vaddr_in_file, 0x100);
  ASSERT_EQ(entries[0].execution_type, CallChainExecutionType::INTERPRETED_JVM_METHOD);
}

TEST_F(CallChainReportBuilderTest, remove_art_frame_only_near_jvm_method) {
  // Test option: remove_art_frame = true, convert_jit_frame = true.
  // The callchain should not remove ART symbols not near a JVM method.
  std::vector<uint64_t> fake_ips = {
      0x1000,  // art_func1
      0x0,     // native_func1
      0x2000,  // java_method1 in dex file
      0x0,     // native_func1
      0x1000,  // art_func1
  };
  CallChainReportBuilder builder(thread_tree);
  std::vector<CallChainReportEntry> entries = builder.Build(thread, fake_ips, 0);
  ASSERT_EQ(entries.size(), 5);
  for (size_t i : {0, 4}) {
    ASSERT_EQ(entries[i].ip, 0x1000);
    ASSERT_STREQ(entries[i].symbol->Name(), "art_func1");
    ASSERT_EQ(entries[i].dso->Path(), fake_interpreter_path);
    ASSERT_EQ(entries[i].vaddr_in_file, 0);
    ASSERT_EQ(entries[i].execution_type, CallChainExecutionType::NATIVE_METHOD);
  }
  for (size_t i : {1, 3}) {
    ASSERT_EQ(entries[i].ip, 0x0);
    ASSERT_STREQ(entries[i].symbol->Name(), "native_func1");
    ASSERT_EQ(entries[i].dso->Path(), fake_native_lib_path);
    ASSERT_EQ(entries[i].vaddr_in_file, 0);
    ASSERT_EQ(entries[i].execution_type, CallChainExecutionType::NATIVE_METHOD);
  }

  ASSERT_EQ(entries[2].ip, 0x2000);
  ASSERT_STREQ(entries[2].symbol->Name(), "java_method1");
  ASSERT_EQ(entries[2].dso->Path(), fake_dex_file_path);
  ASSERT_EQ(entries[2].vaddr_in_file, 0x0);
  ASSERT_EQ(entries[2].execution_type, CallChainExecutionType::INTERPRETED_JVM_METHOD);
}

TEST_F(CallChainReportBuilderTest, keep_art_jni_method) {
  // Test option: remove_art_frame = true.
  // The callchain should remove art_jni_trampoline, but keep jni methods.
  std::vector<uint64_t> fake_ips = {
      0x1200,  // art::Method_invoke(_JNIEnv*, _jobject*, _jobject*, _jobjectArray*)
      0x100,   // art_jni_trampoline
      0x2000,  // java_method1 in dex file
      0x1200,  // art::Method_invoke(_JNIEnv*, _jobject*, _jobject*, _jobjectArray*)
      0x100,   // art_jni_trampoline
  };
  CallChainReportBuilder builder(thread_tree);
  std::vector<CallChainReportEntry> entries = builder.Build(thread, fake_ips, 0);
  ASSERT_EQ(entries.size(), 3);
  for (size_t i : {0, 2}) {
    ASSERT_EQ(entries[i].ip, 0x1200);
    ASSERT_STREQ(entries[i].symbol->DemangledName(),
                 "art::Method_invoke(_JNIEnv*, _jobject*, _jobject*, _jobjectArray*)");
    ASSERT_EQ(entries[i].dso->Path(), fake_interpreter_path);
    ASSERT_EQ(entries[i].vaddr_in_file, 0x200);
    ASSERT_EQ(entries[i].execution_type, CallChainExecutionType::NATIVE_METHOD);
  }
  ASSERT_EQ(entries[1].ip, 0x2000);
  ASSERT_STREQ(entries[1].symbol->Name(), "java_method1");
  ASSERT_EQ(entries[1].dso->Path(), fake_dex_file_path);
  ASSERT_EQ(entries[1].vaddr_in_file, 0x0);
  ASSERT_EQ(entries[1].execution_type, CallChainExecutionType::INTERPRETED_JVM_METHOD);
}

TEST_F(CallChainReportBuilderTest, add_proguard_mapping_file) {
  std::vector<uint64_t> fake_ips = {
      0x2200,  // 2200,  // obfuscated_class.obfuscated_java_method
      0x3200,  // 3200,  // obfuscated_class.obfuscated_java_method2
  };
  CallChainReportBuilder builder(thread_tree);
  // Symbol names aren't changed when not given proguard mapping files.
  std::vector<CallChainReportEntry> entries = builder.Build(thread, fake_ips, 0);
  ASSERT_EQ(entries.size(), 2);
  ASSERT_EQ(entries[0].ip, 0x2200);
  ASSERT_STREQ(entries[0].symbol->DemangledName(), "obfuscated_class.obfuscated_java_method");
  ASSERT_EQ(entries[0].dso->Path(), fake_dex_file_path);
  ASSERT_EQ(entries[0].vaddr_in_file, 0x200);
  ASSERT_EQ(entries[0].execution_type, CallChainExecutionType::INTERPRETED_JVM_METHOD);
  ASSERT_EQ(entries[1].ip, 0x3200);
  ASSERT_STREQ(entries[1].symbol->DemangledName(), "obfuscated_class.obfuscated_java_method2");
  ASSERT_EQ(entries[1].dso->Path(), fake_jit_cache_path);
  ASSERT_EQ(entries[1].vaddr_in_file, 0x3200);
  ASSERT_EQ(entries[1].execution_type, CallChainExecutionType::JIT_JVM_METHOD);

  // Symbol names are changed when given a proguard mapping file.
  TemporaryFile tmpfile;
  close(tmpfile.release());
  ASSERT_TRUE(android::base::WriteStringToFile(
      "android.support.v4.app.RemoteActionCompatParcelizer -> obfuscated_class:\n"
      "    13:13:androidx.core.app.RemoteActionCompat read(androidx.versionedparcelable.Versioned"
      "Parcel) -> obfuscated_java_method\n"
      "    13:13:androidx.core.app.RemoteActionCompat "
      "android.support.v4.app.RemoteActionCompatParcelizer.read2(androidx.versionedparcelable."
      "VersionedParcel) -> obfuscated_java_method2",
      tmpfile.path));
  builder.AddProguardMappingFile(tmpfile.path);
  entries = builder.Build(thread, fake_ips, 0);
  ASSERT_EQ(entries.size(), 2);
  ASSERT_EQ(entries[0].ip, 0x2200);
  ASSERT_STREQ(entries[0].symbol->DemangledName(),
               "android.support.v4.app.RemoteActionCompatParcelizer.read");
  ASSERT_EQ(entries[0].dso->Path(), fake_dex_file_path);
  ASSERT_EQ(entries[0].vaddr_in_file, 0x200);
  ASSERT_EQ(entries[0].execution_type, CallChainExecutionType::INTERPRETED_JVM_METHOD);
  ASSERT_EQ(entries[1].ip, 0x3200);
  ASSERT_STREQ(entries[1].symbol->DemangledName(),
               "android.support.v4.app.RemoteActionCompatParcelizer.read2");
  ASSERT_EQ(entries[1].dso->Path(), fake_jit_cache_path);
  ASSERT_EQ(entries[1].vaddr_in_file, 0x3200);
  ASSERT_EQ(entries[1].execution_type, CallChainExecutionType::JIT_JVM_METHOD);
}
