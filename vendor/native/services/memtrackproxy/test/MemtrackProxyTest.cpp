/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <aidl/android/hardware/memtrack/DeviceInfo.h>
#include <aidl/android/hardware/memtrack/IMemtrack.h>
#include <aidl/android/hardware/memtrack/MemtrackRecord.h>
#include <aidl/android/hardware/memtrack/MemtrackType.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <gtest/gtest.h>
#include <unistd.h>

using aidl::android::hardware::memtrack::DeviceInfo;
using aidl::android::hardware::memtrack::IMemtrack;
using aidl::android::hardware::memtrack::MemtrackRecord;
using aidl::android::hardware::memtrack::MemtrackType;

class MemtrackProxyTest : public ::testing::Test {
public:
    virtual void SetUp() override {
        const char* kMemtrackProxyService = "memtrack.proxy";
        auto memtrackProxyBinder =
                ndk::SpAIBinder(AServiceManager_waitForService(kMemtrackProxyService));
        memtrack_proxy_ = IMemtrack::fromBinder(memtrackProxyBinder);
        ASSERT_NE(memtrack_proxy_, nullptr);
    }

    std::shared_ptr<IMemtrack> memtrack_proxy_;
};

TEST_F(MemtrackProxyTest, GetMemoryForInvalidPid) {
    int pid = -1;

    for (MemtrackType type : ndk::enum_range<MemtrackType>()) {
        std::vector<MemtrackRecord> records;

        auto status = memtrack_proxy_->getMemory(pid, type, &records);

        EXPECT_EQ(status.getExceptionCode(), EX_ILLEGAL_ARGUMENT);
    }
}

TEST_F(MemtrackProxyTest, GetMemoryForCallingPid) {
    int pid = getpid();

    for (MemtrackType type : ndk::enum_range<MemtrackType>()) {
        std::vector<MemtrackRecord> records;

        auto status = memtrack_proxy_->getMemory(pid, type, &records);

        EXPECT_TRUE(status.isOk());
    }
}

TEST_F(MemtrackProxyTest, GetMemoryForOtherPid) {
    int pid = 1;

    for (MemtrackType type : ndk::enum_range<MemtrackType>()) {
        std::vector<MemtrackRecord> records;

        auto status = memtrack_proxy_->getMemory(pid, type, &records);

        // Test is run as root
        EXPECT_TRUE(status.isOk());
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
