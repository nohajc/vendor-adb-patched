/*
 * Copyright 2022 The Android Open Source Project
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

#include <ftl/fake_guard.h>
#include <gtest/gtest.h>

#include <functional>
#include <mutex>

namespace android::test {

// Keep in sync with example usage in header file.
TEST(FakeGuard, Example) {
  struct {
    std::mutex mutex;
    int x FTL_ATTRIBUTE(guarded_by(mutex)) = -1;

    int f() {
      {
        ftl::FakeGuard guard(mutex);
        x = 0;
      }

      return FTL_FAKE_GUARD(mutex, x + 1);
    }

    std::function<int()> g() const {
      return [this]() FTL_FAKE_GUARD(mutex) { return x; };
    }
  } s;

  EXPECT_EQ(s.f(), 1);
  EXPECT_EQ(s.g()(), 0);
}

}  // namespace android::test
