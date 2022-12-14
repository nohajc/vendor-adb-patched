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

#include <android-base/test_utils.h>

#include "get_test_data.h"
#include "kallsyms.h"
#include "test_util.h"

using namespace simpleperf;

static bool ModulesMatch(const char* p, const char* q) {
  if (p == nullptr && q == nullptr) {
    return true;
  }
  if (p != nullptr && q != nullptr) {
    return strcmp(p, q) == 0;
  }
  return false;
}

static bool KernelSymbolsMatch(const KernelSymbol& sym1, const KernelSymbol& sym2) {
  return sym1.addr == sym2.addr && sym1.type == sym2.type && strcmp(sym1.name, sym2.name) == 0 &&
         ModulesMatch(sym1.module, sym2.module);
}

TEST(kallsyms, ProcessKernelSymbols) {
  std::string data =
      "ffffffffa005c4e4 d __warned.41698   [libsas]\n"
      "aaaaaaaaaaaaaaaa T _text\n"
      "cccccccccccccccc c ccccc\n";
  KernelSymbol expected_symbol;
  expected_symbol.addr = 0xffffffffa005c4e4ULL;
  expected_symbol.type = 'd';
  expected_symbol.name = "__warned.41698";
  expected_symbol.module = "libsas";
  ASSERT_TRUE(ProcessKernelSymbols(
      data, std::bind(&KernelSymbolsMatch, std::placeholders::_1, expected_symbol)));

  expected_symbol.addr = 0xaaaaaaaaaaaaaaaaULL;
  expected_symbol.type = 'T';
  expected_symbol.name = "_text";
  expected_symbol.module = nullptr;
  ASSERT_TRUE(ProcessKernelSymbols(
      data, std::bind(&KernelSymbolsMatch, std::placeholders::_1, expected_symbol)));

  expected_symbol.name = "non_existent_symbol";
  ASSERT_FALSE(ProcessKernelSymbols(
      data, std::bind(&KernelSymbolsMatch, std::placeholders::_1, expected_symbol)));
}

#if defined(__ANDROID__)
TEST(kallsyms, GetKernelStartAddress) {
  TEST_REQUIRE_ROOT();
  ASSERT_NE(GetKernelStartAddress(), 0u);
}

TEST(kallsyms, LoadKernelSymbols) {
  TEST_REQUIRE_ROOT();
  std::string kallsyms;
  ASSERT_TRUE(LoadKernelSymbols(&kallsyms));
}

TEST(kallsyms, print_warning) {
  TEST_REQUIRE_NON_ROOT();
  const std::string warning_msg = "Access to kernel symbol addresses is restricted.";
  CapturedStderr capture;

  // Call each function requiring kernel addresses once. Check if the warning is printed.
  ResetKernelAddressWarning();
  ASSERT_EQ(0, GetKernelStartAddress());
  capture.Stop();
  ASSERT_NE(capture.str().find(warning_msg), std::string::npos);

  capture.Reset();
  capture.Start();
  ResetKernelAddressWarning();
  std::string kallsyms;
  ASSERT_FALSE(LoadKernelSymbols(&kallsyms));
  capture.Stop();
  ASSERT_NE(capture.str().find(warning_msg), std::string::npos);

  capture.Reset();
  capture.Start();
  ResetKernelAddressWarning();
  ASSERT_TRUE(GetLoadedModules().empty());
  capture.Stop();
  ASSERT_NE(capture.str().find(warning_msg), std::string::npos);

  // Call functions requiring kernel addresses more than once.
  // Check if the kernel address warning is only printed once.
  capture.Reset();
  capture.Start();
  ResetKernelAddressWarning();
  for (int i = 0; i < 2; i++) {
    ASSERT_EQ(0, GetKernelStartAddress());
    ASSERT_FALSE(LoadKernelSymbols(&kallsyms));
    ASSERT_TRUE(GetLoadedModules().empty());
  }
  capture.Stop();
  std::string output = capture.str();
  auto pos = output.find(warning_msg);
  ASSERT_NE(pos, std::string::npos);
  ASSERT_EQ(output.find(warning_msg, pos + warning_msg.size()), std::string::npos);
}
#endif  // defined(__ANDROID__)
