/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "JITDebugReader_impl.h"

#include <android-base/file.h>
#include <android-base/test_utils.h>

#include <gtest/gtest.h>

using namespace simpleperf;

TEST(TempSymFile, smoke) {
  TemporaryFile tmpfile;
  std::unique_ptr<TempSymFile> symfile = TempSymFile::Create(tmpfile.path, false);
  ASSERT_TRUE(symfile);
  // If we write entries starting from offset 0, libunwindstack will treat the whole file as an elf
  // file in its elf cache. So make sure we don't start from offset 0.
  uint64_t offset = symfile->GetOffset();
  ASSERT_NE(offset, 0u);

  // Write data and read it back.
  const std::string test_data = "test_data";
  ASSERT_TRUE(symfile->WriteEntry(test_data.c_str(), test_data.size()));
  ASSERT_TRUE(symfile->Flush());

  char buf[16];
  ASSERT_TRUE(android::base::ReadFullyAtOffset(tmpfile.fd, buf, test_data.size(), offset));
  ASSERT_EQ(strncmp(test_data.c_str(), buf, test_data.size()), 0);
}
