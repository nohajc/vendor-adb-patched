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

#include "read_symbol_map.h"

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "dso.h"

using namespace simpleperf;

TEST(read_symbol_map, smoke) {
  std::string content(
      "\n"  // skip
      "   0x2000 0x20 two \n"
      "0x4000\n"            // skip
      "       0x40 four\n"  // skip
      "0x1000 0x10 one\n"
      "     \n"                // skip
      "0x5000 0x50five\n"      // skip
      " skip this line\n"      // skip
      "0x6000 0x60 six six\n"  // skip
      "0x3000 48   three   \n");

  auto symbols = ReadSymbolMapFromString(content);

  ASSERT_EQ(3u, symbols.size());

  ASSERT_EQ(0x1000, symbols[0].addr);
  ASSERT_EQ(0x10, symbols[0].len);
  ASSERT_STREQ("one", symbols[0].Name());

  ASSERT_EQ(0x2000, symbols[1].addr);
  ASSERT_EQ(0x20, symbols[1].len);
  ASSERT_STREQ("two", symbols[1].Name());

  ASSERT_EQ(0x3000, symbols[2].addr);
  ASSERT_EQ(0x30, symbols[2].len);
  ASSERT_STREQ("three", symbols[2].Name());
}
