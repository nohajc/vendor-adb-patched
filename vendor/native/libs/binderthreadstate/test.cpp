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

#include <BnAidlStuff.h>
#include <android-base/logging.h>
#include <binder/IServiceManager.h>
#include <binderthreadstate/CallerUtils.h>
#include <binderthreadstateutilstest/1.0/IHidlStuff.h>
#include <gtest/gtest.h>
#include <hidl/HidlTransportSupport.h>
#include <linux/prctl.h>
#include <sys/prctl.h>

using android::BinderCallType;
using android::defaultServiceManager;
using android::getCurrentServingCall;
using android::getService;
using android::OK;
using android::sp;
using android::String16;
using android::binder::Status;
using android::hardware::Return;
using binderthreadstateutilstest::V1_0::IHidlStuff;

constexpr size_t kP1Id = 1;
constexpr size_t kP2Id = 2;

// AIDL and HIDL are in separate namespaces so using same service names
std::string id2name(size_t id) {
    return "libbinderthreadstateutils-" + std::to_string(id);
}

// There are two servers calling each other recursively like this.
//
// P1           P2
// |  --HIDL-->  |
// |  <--HIDL--  |
// |  --AIDL-->  |
// |  <--AIDL--  |
// |  --HIDL-->  |
// |  <--HIDL--  |
// |  --AIDL-->  |
// |  <--AIDL--  |
//   ..........
//
// Calls always come in pairs (AIDL returns AIDL, HIDL returns HIDL) because
// this means that P1 always has a 'waitForResponse' call which can service the
// returning call and continue the recursion. Of course, with more threads, more
// complicated calls are possible, but this should do here.

static void callHidl(size_t id, int32_t idx) {
    auto stuff = IHidlStuff::getService(id2name(id));
    CHECK(stuff->call(idx).isOk());
}

static void callAidl(size_t id, int32_t idx) {
    sp<IAidlStuff> stuff;
    CHECK(OK == android::getService<IAidlStuff>(String16(id2name(id).c_str()), &stuff));
    CHECK(stuff->call(idx).isOk());
}

class HidlServer : public IHidlStuff {
public:
    HidlServer(size_t thisId, size_t otherId) : thisId(thisId), otherId(otherId) {}
    size_t thisId;
    size_t otherId;

    Return<void> callLocal() {
        CHECK(BinderCallType::NONE == getCurrentServingCall());
        return android::hardware::Status::ok();
    }
    Return<void> call(int32_t idx) {
        LOG(INFO) << "HidlServer CALL " << thisId << " to " << otherId << " at idx: " << idx
                  << " with tid: " << gettid();
        CHECK(BinderCallType::HWBINDER == getCurrentServingCall());
        if (idx > 0) {
            if (thisId == kP1Id && idx % 4 < 2) {
                callHidl(otherId, idx - 1);
            } else {
                callAidl(otherId, idx - 1);
            }
        }
        CHECK(BinderCallType::HWBINDER == getCurrentServingCall());
        return android::hardware::Status::ok();
    }
};
class AidlServer : public BnAidlStuff {
public:
    AidlServer(size_t thisId, size_t otherId) : thisId(thisId), otherId(otherId) {}
    size_t thisId;
    size_t otherId;

    Status callLocal() {
        CHECK(BinderCallType::NONE == getCurrentServingCall());
        return Status::ok();
    }
    Status call(int32_t idx) {
        LOG(INFO) << "AidlServer CALL " << thisId << " to " << otherId << " at idx: " << idx
                  << " with tid: " << gettid();
        CHECK(BinderCallType::BINDER == getCurrentServingCall());
        if (idx > 0) {
            if (thisId == kP2Id && idx % 4 < 2) {
                callHidl(otherId, idx - 1);
            } else {
                callAidl(otherId, idx - 1);
            }
        }
        CHECK(BinderCallType::BINDER == getCurrentServingCall());
        return Status::ok();
    }
};

TEST(BinderThreadState, LocalHidlCall) {
    sp<IHidlStuff> server = new HidlServer(0, 0);
    EXPECT_TRUE(server->callLocal().isOk());
}

TEST(BinderThreadState, LocalAidlCall) {
    sp<IAidlStuff> server = new AidlServer(0, 0);
    EXPECT_TRUE(server->callLocal().isOk());
}

TEST(BindThreadState, RemoteHidlCall) {
    auto stuff = IHidlStuff::getService(id2name(kP1Id));
    ASSERT_NE(nullptr, stuff);
    ASSERT_TRUE(stuff->call(0).isOk());
}
TEST(BindThreadState, RemoteAidlCall) {
    sp<IAidlStuff> stuff;
    ASSERT_EQ(OK, android::getService<IAidlStuff>(String16(id2name(kP1Id).c_str()), &stuff));
    ASSERT_NE(nullptr, stuff);
    ASSERT_TRUE(stuff->call(0).isOk());
}

TEST(BindThreadState, RemoteNestedStartHidlCall) {
    auto stuff = IHidlStuff::getService(id2name(kP1Id));
    ASSERT_NE(nullptr, stuff);
    ASSERT_TRUE(stuff->call(100).isOk());
}
TEST(BindThreadState, RemoteNestedStartAidlCall) {
    sp<IAidlStuff> stuff;
    ASSERT_EQ(OK, android::getService<IAidlStuff>(String16(id2name(kP1Id).c_str()), &stuff));
    ASSERT_NE(nullptr, stuff);
    EXPECT_TRUE(stuff->call(100).isOk());
}

int server(size_t thisId, size_t otherId) {
    // AIDL
    android::ProcessState::self()->setThreadPoolMaxThreadCount(1);
    sp<AidlServer> aidlServer = new AidlServer(thisId, otherId);
    CHECK(OK == defaultServiceManager()->addService(String16(id2name(thisId).c_str()), aidlServer));
    android::ProcessState::self()->startThreadPool();

    // HIDL
    android::hardware::configureRpcThreadpool(1, true /*callerWillJoin*/);
    sp<IHidlStuff> hidlServer = new HidlServer(thisId, otherId);
    CHECK(OK == hidlServer->registerAsService(id2name(thisId).c_str()));
    android::hardware::joinRpcThreadpool();

    return EXIT_FAILURE;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    android::hardware::details::setTrebleTestingOverride(true);
    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        return server(kP1Id, kP2Id);
    }
    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        return server(kP2Id, kP1Id);
    }

    android::waitForService<IAidlStuff>(String16(id2name(kP1Id).c_str()));
    android::hardware::details::waitForHwService(IHidlStuff::descriptor, id2name(kP1Id).c_str());
    android::waitForService<IAidlStuff>(String16(id2name(kP2Id).c_str()));
    android::hardware::details::waitForHwService(IHidlStuff::descriptor, id2name(kP2Id).c_str());

    return RUN_ALL_TESTS();
}
