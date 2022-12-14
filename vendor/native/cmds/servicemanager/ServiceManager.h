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

#pragma once

#include <android/os/BnServiceManager.h>
#include <android/os/IClientCallback.h>
#include <android/os/IServiceCallback.h>

#include "Access.h"

namespace android {

using os::IClientCallback;
using os::IServiceCallback;
using os::ServiceDebugInfo;

class ServiceManager : public os::BnServiceManager, public IBinder::DeathRecipient {
public:
    ServiceManager(std::unique_ptr<Access>&& access);
    ~ServiceManager();

    // getService will try to start any services it cannot find
    binder::Status getService(const std::string& name, sp<IBinder>* outBinder) override;
    binder::Status checkService(const std::string& name, sp<IBinder>* outBinder) override;
    binder::Status addService(const std::string& name, const sp<IBinder>& binder,
                              bool allowIsolated, int32_t dumpPriority) override;
    binder::Status listServices(int32_t dumpPriority, std::vector<std::string>* outList) override;
    binder::Status registerForNotifications(const std::string& name,
                                            const sp<IServiceCallback>& callback) override;
    binder::Status unregisterForNotifications(const std::string& name,
                                              const sp<IServiceCallback>& callback) override;

    binder::Status isDeclared(const std::string& name, bool* outReturn) override;
    binder::Status getDeclaredInstances(const std::string& interface, std::vector<std::string>* outReturn) override;
    binder::Status updatableViaApex(const std::string& name,
                                    std::optional<std::string>* outReturn) override;
    binder::Status registerClientCallback(const std::string& name, const sp<IBinder>& service,
                                          const sp<IClientCallback>& cb) override;
    binder::Status tryUnregisterService(const std::string& name, const sp<IBinder>& binder) override;
    binder::Status getServiceDebugInfo(std::vector<ServiceDebugInfo>* outReturn) override;
    void binderDied(const wp<IBinder>& who) override;
    void handleClientCallbacks();

protected:
    virtual void tryStartService(const std::string& name);

private:
    struct Service {
        sp<IBinder> binder; // not null
        bool allowIsolated;
        int32_t dumpPriority;
        bool hasClients = false; // notifications sent on true -> false.
        bool guaranteeClient = false; // forces the client check to true
        pid_t debugPid = 0; // the process in which this service runs

        // the number of clients of the service, including servicemanager itself
        ssize_t getNodeStrongRefCount();
    };

    using ServiceCallbackMap = std::map<std::string, std::vector<sp<IServiceCallback>>>;
    using ClientCallbackMap = std::map<std::string, std::vector<sp<IClientCallback>>>;
    using ServiceMap = std::map<std::string, Service>;

    // removes a callback from mNameToRegistrationCallback, removing it if the vector is empty
    // this updates iterator to the next location
    void removeRegistrationCallback(const wp<IBinder>& who,
                        ServiceCallbackMap::iterator* it,
                        bool* found);
    ssize_t handleServiceClientCallback(const std::string& serviceName, bool isCalledOnInterval);
     // Also updates mHasClients (of what the last callback was)
    void sendClientCallbackNotifications(const std::string& serviceName, bool hasClients);
    // removes a callback from mNameToClientCallback, deleting the entry if the vector is empty
    // this updates the iterator to the next location
    void removeClientCallback(const wp<IBinder>& who, ClientCallbackMap::iterator* it);

    sp<IBinder> tryGetService(const std::string& name, bool startIfNotFound);

    ServiceMap mNameToService;
    ServiceCallbackMap mNameToRegistrationCallback;
    ClientCallbackMap mNameToClientCallback;

    std::unique_ptr<Access> mAccess;
};

}  // namespace android
