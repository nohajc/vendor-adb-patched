/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include <gmock/gmock.h>

#include <binder/Binder.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>

#include "ServiceManager.h"

using android::sp;
using android::BBinder;
using android::IBinder;
using android::OK;
using android::status_t;
using android::ServiceManager;
using android::String16;
using android::IServiceManager;
using testing::ElementsAre;

static sp<IBinder> getBinder() {
    class LinkableBinder : public BBinder {
        status_t linkToDeath(const sp<DeathRecipient>&, void*, uint32_t) override {
            // let SM linkToDeath
            return OK;
        }
    };

    return new LinkableBinder;
}

TEST(AddService, HappyHappy) {
    auto sm = new ServiceManager();
    EXPECT_EQ(sm->addService(String16("foo"), getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT), OK);
}

TEST(AddService, HappyOverExistingService) {
    auto sm = new ServiceManager();
    EXPECT_EQ(sm->addService(String16("foo"), getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT), OK);
    EXPECT_EQ(sm->addService(String16("foo"), getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT), OK);
}

TEST(GetService, HappyHappy) {
    auto sm = new ServiceManager();
    sp<IBinder> service = getBinder();

    EXPECT_EQ(sm->addService(String16("foo"), service, false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT), OK);

    EXPECT_EQ(sm->getService(String16("foo")), service);
}

TEST(GetService, NonExistant) {
    auto sm = new ServiceManager();

    EXPECT_EQ(sm->getService(String16("foo")), nullptr);
}

TEST(ListServices, AllServices) {
    auto sm = new ServiceManager();

    EXPECT_EQ(sm->addService(String16("sd"), getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT), OK);
    EXPECT_EQ(sm->addService(String16("sc"), getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_NORMAL), OK);
    EXPECT_EQ(sm->addService(String16("sb"), getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_HIGH), OK);
    EXPECT_EQ(sm->addService(String16("sa"), getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_CRITICAL), OK);

    android::Vector<String16> out = sm->listServices(IServiceManager::DUMP_FLAG_PRIORITY_ALL);

    // all there and in the right order
    EXPECT_THAT(out, ElementsAre(String16("sa"), String16("sb"), String16("sc"),
        String16("sd")));
}

TEST(WaitForService, NonExistant) {
    auto sm = new ServiceManager();

    EXPECT_EQ(sm->waitForService(String16("foo")), nullptr);
}

TEST(WaitForService, HappyHappy) {
    auto sm = new ServiceManager();
    sp<IBinder> service = getBinder();

    EXPECT_EQ(sm->addService(String16("foo"), service, false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT), OK);

    EXPECT_EQ(sm->waitForService(String16("foo")), service);
}

TEST(IsDeclared, NonExistant) {
    auto sm = new ServiceManager();

    EXPECT_FALSE(sm->isDeclared(String16("foo")));
}

TEST(IsDeclared, HappyHappy) {
    auto sm = new ServiceManager();
    sp<IBinder> service = getBinder();

    EXPECT_EQ(sm->addService(String16("foo"), service, false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT), OK);

    EXPECT_TRUE(sm->isDeclared(String16("foo")));
}
