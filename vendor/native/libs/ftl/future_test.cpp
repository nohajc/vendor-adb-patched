/*
 * Copyright 2020 The Android Open Source Project
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

#include <ftl/future.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <future>
#include <string>
#include <thread>
#include <vector>

namespace android::test {

// Keep in sync with example usage in header file.
TEST(Future, Example) {
  {
    auto future = ftl::defer([](int x) { return x + 1; }, 99);
    EXPECT_EQ(future.get(), 100);
  }
  {
    auto future = ftl::yield(42);
    EXPECT_EQ(future.get(), 42);
  }
  {
    auto ptr = std::make_unique<char>('!');
    auto future = ftl::yield(std::move(ptr));
    EXPECT_EQ(*future.get(), '!');
  }
  {
    auto future = ftl::yield(123);
    std::future<char> futures[] = {ftl::yield('a'), ftl::yield('b')};

    std::future<char> chain = ftl::chain(std::move(future))
                                  .then([](int x) { return static_cast<size_t>(x % 2); })
                                  .then([&futures](size_t i) { return std::move(futures[i]); });

    EXPECT_EQ(chain.get(), 'b');
  }
}

namespace {

using ByteVector = std::vector<uint8_t>;

ByteVector decrement(ByteVector bytes) {
  std::transform(bytes.begin(), bytes.end(), bytes.begin(), [](auto b) { return b - 1; });
  return bytes;
}

}  // namespace

TEST(Future, Chain) {
  std::packaged_task<const char*()> fetch_string([] { return "ifmmp-"; });

  std::packaged_task<ByteVector(std::string)> append_string([](std::string str) {
    str += "!xpsme";
    return ByteVector{str.begin(), str.end()};
  });

  std::packaged_task<std::future<ByteVector>(ByteVector)> decrement_bytes(
      [](ByteVector bytes) { return ftl::defer(decrement, std::move(bytes)); });

  auto fetch = fetch_string.get_future();
  std::thread fetch_thread(std::move(fetch_string));

  std::thread append_thread, decrement_thread;

  EXPECT_EQ(
      "hello, world",
      ftl::chain(std::move(fetch))
          .then([](const char* str) { return std::string(str); })
          .then([&](std::string str) {
            auto append = append_string.get_future();
            append_thread = std::thread(std::move(append_string), std::move(str));
            return append;
          })
          .then([&](ByteVector bytes) {
            auto decrement = decrement_bytes.get_future();
            decrement_thread = std::thread(std::move(decrement_bytes), std::move(bytes));
            return decrement;
          })
          .then([](std::future<ByteVector> bytes) { return bytes; })
          .then([](const ByteVector& bytes) { return std::string(bytes.begin(), bytes.end()); })
          .get());

  fetch_thread.join();
  append_thread.join();
  decrement_thread.join();
}

}  // namespace android::test
