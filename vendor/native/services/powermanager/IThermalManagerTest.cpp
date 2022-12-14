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

#define LOG_TAG "ThermalManagerTest"
//#define LOG_NDEBUG 0

#include <thread>

#include <android/os/BnThermalStatusListener.h>
#include <android/os/IThermalService.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <condition_variable>
#include <gtest/gtest.h>
#include <powermanager/PowerManager.h>
#include <utils/Log.h>

using namespace android;
using namespace android::os;
using namespace std::chrono_literals;

class IThermalServiceTest : public testing::Test,
                            public BnThermalStatusListener{
    public:
        IThermalServiceTest();
        void setThermalOverride(int level);
        virtual binder::Status onStatusChange(int status) override;
        int getStatusFromService();
        void SetUp() override;
        void TearDown() override;
    protected:
        sp<IThermalService> mThermalSvc;
        std::condition_variable mCondition;
        int mListenerStatus;
        int mServiceStatus;
        std::mutex mMutex;
};

IThermalServiceTest::IThermalServiceTest()
 : mListenerStatus(0),
   mServiceStatus(0) {
}

void IThermalServiceTest::setThermalOverride(int level) {
    std::string cmdStr = "cmd thermalservice override-status " + std::to_string(level);
    system(cmdStr.c_str());
}

binder::Status IThermalServiceTest::onStatusChange(int status) {
    std::unique_lock<std::mutex> lock(mMutex);
    mListenerStatus = status;
    ALOGI("IThermalServiceTest::notifyListener %d", mListenerStatus);
    mCondition.notify_all();
    return binder::Status::ok();
}

int IThermalServiceTest::getStatusFromService() {
    int status;
    binder::Status ret = mThermalSvc->getCurrentThermalStatus(&status);
    if (ret.isOk()) {
        return status;
    } else {
        return BAD_VALUE;
    }
}

void IThermalServiceTest::SetUp() {
    setThermalOverride(0);
    // use checkService() to avoid blocking if thermal service is not up yet
    sp<IBinder> binder =
        defaultServiceManager()->checkService(String16("thermalservice"));
    EXPECT_NE(binder, nullptr);
    mThermalSvc = interface_cast<IThermalService>(binder);
    EXPECT_NE(mThermalSvc, nullptr);
    bool success = false;
    binder::Status ret = mThermalSvc->registerThermalStatusListener(this, &success);
    ASSERT_TRUE(success);
    ASSERT_TRUE(ret.isOk());
    // Wait for listener called after registration, shouldn't timeout
    std::unique_lock<std::mutex> lock(mMutex);
    EXPECT_NE(mCondition.wait_for(lock, 1s), std::cv_status::timeout);
}

void IThermalServiceTest::TearDown() {
    bool success = false;
    binder::Status ret = mThermalSvc->unregisterThermalStatusListener(this, &success);
    ASSERT_TRUE(success);
    ASSERT_TRUE(ret.isOk());
}

class IThermalListenerTest : public IThermalServiceTest, public testing::WithParamInterface<int32_t> {
  public:
    static auto PrintParam(const testing::TestParamInfo<ParamType> &info) {
        return std::to_string(info.param);
    }
};

TEST_P(IThermalListenerTest, TestListener) {
    int level = GetParam();
    std::unique_lock<std::mutex> lock(mMutex);
    // Set the override thermal status
    setThermalOverride(level);
    // Wait for listener called, shouldn't timeout
    EXPECT_NE(mCondition.wait_for(lock, 1s), std::cv_status::timeout);
    // Check the result
    EXPECT_EQ(level, mListenerStatus);
    ALOGI("Thermal listener status %d, expecting %d", mListenerStatus, level);
}

INSTANTIATE_TEST_SUITE_P(TestListenerLevels, IThermalListenerTest, testing::Range(
        static_cast<int>(ThermalStatus::THERMAL_STATUS_LIGHT),
        static_cast<int>(ThermalStatus::THERMAL_STATUS_SHUTDOWN)),
        IThermalListenerTest::PrintParam);

class IThermalLevelTest : public IThermalServiceTest, public testing::WithParamInterface<int32_t> {
  public:
    static auto PrintParam(const testing::TestParamInfo<ParamType> &info) {
        return std::to_string(info.param);
    }
};

TEST_P(IThermalLevelTest, TestGetStatusLevel) {
    int level = GetParam();
    setThermalOverride(level);
    mServiceStatus = getStatusFromService();
    EXPECT_EQ(level, mServiceStatus);
}

INSTANTIATE_TEST_SUITE_P(TestStatusLevels, IThermalLevelTest, testing::Range(
        static_cast<int>(ThermalStatus::THERMAL_STATUS_NONE),
        static_cast<int>(ThermalStatus::THERMAL_STATUS_SHUTDOWN)),
        IThermalLevelTest::PrintParam);

int main(int argc, char **argv) {
    std::unique_ptr<std::thread> binderLoop;
    binderLoop = std::make_unique<std::thread>(
            [&] { IPCThreadState::self()->joinThreadPool(true); });

    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);

    return status;
}