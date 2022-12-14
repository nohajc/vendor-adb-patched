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

#include <stdio.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <bootloader_message/bootloader_message.h>

namespace {
using ::testing::StartsWith;

int mtectrl(const char* arg) {
  std::string cmd = "mtectrl -t /data/local/tmp/misc_memtag ";
  cmd += arg;
  return system(cmd.c_str());
}

std::string GetMisc() {
  std::string data;
  CHECK(android::base::ReadFileToString("/data/local/tmp/misc_memtag", &data, false));
  return data;
}

std::string TestProperty() {
  return android::base::GetProperty("arm64.memtag.test_bootctl", "");
}
}  // namespace

class MteCtrlTest : public ::testing::Test {
  void SetUp() override {
    // Empty fake misc partition.
    int fd = creat("/data/local/tmp/misc_memtag", 0600);
    CHECK(fd != -1);
    CHECK(ftruncate(fd, sizeof(misc_memtag_message)) != -1);
    close(fd);
    android::base::SetProperty("arm64.memtag.test_bootctl", "INVALID");
  }
  void TearDown() override {
    CHECK(unlink("/data/local/tmp/misc_memtag") == 0);
  }
};

TEST_F(MteCtrlTest, invalid) {
  EXPECT_NE(mtectrl("memtag-invalid"), 0);
  EXPECT_NE(mtectrl("memtag override-invalid"), 0);
}

TEST_F(MteCtrlTest, set_once) {
  ASSERT_EQ(mtectrl("memtag-once"), 0);
  EXPECT_THAT(GetMisc(), StartsWith("\x01\x5a\xfe\xfe\x5a\x02"));
}

TEST_F(MteCtrlTest, set_once_kernel) {
  ASSERT_EQ(mtectrl("memtag-once,memtag-kernel"), 0);
  EXPECT_THAT(GetMisc(), StartsWith("\x01\x5a\xfe\xfe\x5a\x06"));
}

TEST_F(MteCtrlTest, set_memtag) {
  ASSERT_EQ(mtectrl("memtag"), 0);
  EXPECT_THAT(GetMisc(), StartsWith("\x01\x5a\xfe\xfe\x5a\x01"));
}

TEST_F(MteCtrlTest, set_memtag_force_off) {
  ASSERT_EQ(mtectrl("memtag force_off"), 0);
  EXPECT_THAT(GetMisc(), StartsWith("\x01\x5a\xfe\xfe\x5a\x10"));
}

TEST_F(MteCtrlTest, read_memtag) {
  ASSERT_EQ(mtectrl("memtag"), 0);
  ASSERT_EQ(mtectrl("-s arm64.memtag.test_bootctl"), 0);
  EXPECT_EQ(TestProperty(), "memtag");
}

TEST_F(MteCtrlTest, read_invalid_memtag_message) {
  misc_memtag_message m = {.version = 1, .magic = 0xffff, .memtag_mode = MISC_MEMTAG_MODE_MEMTAG};
  std::string m_str(reinterpret_cast<char*>(&m), sizeof(m));
  android::base::WriteStringToFile(m_str, "/data/local/tmp/misc_memtag");
  ASSERT_EQ(mtectrl("-s arm64.memtag.test_bootctl"), 0);
  EXPECT_EQ(TestProperty(), "");
}

TEST_F(MteCtrlTest, read_invalid_memtag_mode) {
  misc_memtag_message m = {.version = MISC_MEMTAG_MESSAGE_VERSION,
                           .magic = MISC_MEMTAG_MAGIC_HEADER,
                           .memtag_mode = MISC_MEMTAG_MODE_MEMTAG | 1u << 31};
  std::string m_str(reinterpret_cast<char*>(&m), sizeof(m));
  android::base::WriteStringToFile(m_str, "/data/local/tmp/misc_memtag");
  ASSERT_NE(mtectrl("-s arm64.memtag.test_bootctl"), 0);
  EXPECT_EQ(TestProperty(), "memtag");
}

TEST_F(MteCtrlTest, set_read_memtag) {
  ASSERT_EQ(mtectrl("-s arm64.memtag.test_bootctl memtag"), 0);
  EXPECT_EQ(TestProperty(), "memtag");
}

TEST_F(MteCtrlTest, set_read_force_off) {
  ASSERT_EQ(mtectrl("-s arm64.memtag.test_bootctl memtag,memtag-once force_off"), 0);
  EXPECT_EQ(TestProperty(), "memtag-once,memtag-off");
}

TEST_F(MteCtrlTest, override) {
  ASSERT_EQ(mtectrl("memtag"), 0);
  ASSERT_EQ(mtectrl("memtag-once"), 0);
  EXPECT_THAT(GetMisc(), StartsWith("\x01\x5a\xfe\xfe\x5a\x02"));
}

TEST_F(MteCtrlTest, read_empty) {
  ASSERT_EQ(mtectrl("-s arm64.memtag.test_bootctl"), 0);
  EXPECT_EQ(TestProperty(), "");
}

TEST_F(MteCtrlTest, force_off_invalid_mode) {
  mtectrl("-s arm64.memtag.test_bootctl memtag-invalid force_off");
  EXPECT_EQ(TestProperty(), "memtag-off");
  EXPECT_THAT(GetMisc(), StartsWith("\x01\x5a\xfe\xfe\x5a\x10"));
}

TEST_F(MteCtrlTest, force_on_invalid_mode) {
  mtectrl("-s arm64.memtag.test_bootctl memtag-invalid force_on");
  EXPECT_EQ(TestProperty(), "memtag");
  EXPECT_THAT(GetMisc(), StartsWith("\x01\x5a\xfe\xfe\x5a\x01"));
}

TEST_F(MteCtrlTest, mode_invalid_override) {
  mtectrl("-s arm64.memtag.test_bootctl memtag force_invalid");
  EXPECT_EQ(TestProperty(), "memtag");
  EXPECT_THAT(GetMisc(), StartsWith("\x01\x5a\xfe\xfe\x5a\x01"));
}
