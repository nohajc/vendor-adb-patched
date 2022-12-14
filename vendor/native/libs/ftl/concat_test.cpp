/*
 * Copyright 2021 The Android Open Source Project
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

#include <ftl/concat.h>
#include <gtest/gtest.h>

namespace android::test {

// Keep in sync with example usage in header file.
TEST(Concat, Example) {
  std::string_view name = "Volume";
  ftl::Concat string(ftl::truncated<3>(name), ": ", -3, " dB");

  EXPECT_EQ(string.str(), "Vol: -3 dB");
  EXPECT_EQ(string.c_str()[string.size()], '\0');
}

namespace {

static_assert(ftl::Concat{"foo"}.str() == "foo");
static_assert(ftl::Concat{ftl::truncated<3>("foobar")}.str() == "foo");

constexpr ftl::Concat kConcat{"po", "trz", "ebie"};

static_assert(kConcat.size() == 9);
static_assert(kConcat.max_size() == 9);
static_assert(kConcat.str() == "potrzebie");
static_assert(kConcat.str() == std::string_view(kConcat.c_str()));

constexpr auto concat() {
  return ftl::Concat{ftl::truncated<1>("v???"), ftl::truncated<2>("ee??"),
                     ftl::truncated<3>("ble?"), ftl::truncated<4>("fetz"),
                     ftl::truncated<90>("er")};
}

static_assert(concat().size() == 12);
static_assert(concat().max_size() == 100);
static_assert(concat().str() == "veeblefetzer");
static_assert(concat().str() == std::string_view(concat().c_str()));

}  // namespace
}  // namespace android::test
