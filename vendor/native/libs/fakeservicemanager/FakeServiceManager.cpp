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

#include "fakeservicemanager/FakeServiceManager.h"

namespace android {

FakeServiceManager::FakeServiceManager() {}

sp<IBinder> FakeServiceManager::getService( const String16& name) const {
    // Servicemanager is single-threaded and cannot block. This method exists for legacy reasons.
    return checkService(name);
}

sp<IBinder> FakeServiceManager::checkService( const String16& name) const {
    auto it = mNameToService.find(name);
    if (it == mNameToService.end()) {
        return nullptr;
    }
    return it->second;
}

status_t FakeServiceManager::addService(const String16& name, const sp<IBinder>& service,
                                bool /*allowIsolated*/,
                                int /*dumpsysFlags*/) {
    if (service == nullptr) {
        return UNEXPECTED_NULL;
    }
    mNameToService[name] = service;
    return NO_ERROR;
}

Vector<String16> FakeServiceManager::listServices(int /*dumpsysFlags*/) {
    Vector<String16> services;
    for (auto const& [name, service] : mNameToService) {
        (void) service;
         services.push_back(name);
    }
  return services;
}

IBinder* FakeServiceManager::onAsBinder() {
    return nullptr;
}

sp<IBinder> FakeServiceManager::waitForService(const String16& name) {
    return checkService(name);
}

bool FakeServiceManager::isDeclared(const String16& name) {
    return mNameToService.find(name) != mNameToService.end();
}

Vector<String16> FakeServiceManager::getDeclaredInstances(const String16& name) {
    Vector<String16> out;
    const String16 prefix = name + String16("/");
    for (const auto& [registeredName, service] : mNameToService) {
        (void) service;
        if (registeredName.startsWith(prefix)) {
            out.add(String16(registeredName.string() + prefix.size()));
        }
    }
    return out;
}

std::optional<String16> FakeServiceManager::updatableViaApex(const String16& name) {
    (void)name;
    return std::nullopt;
}

Vector<String16> FakeServiceManager::getUpdatableNames(const String16& apexName) {
    (void)apexName;
    return {};
}

std::optional<IServiceManager::ConnectionInfo> FakeServiceManager::getConnectionInfo(
        const String16& name) {
    (void)name;
    return std::nullopt;
}

status_t FakeServiceManager::registerForNotifications(const String16&,
                                                  const sp<LocalRegistrationCallback>&) {
    return INVALID_OPERATION;
}

status_t FakeServiceManager::unregisterForNotifications(const String16&,
                                                const sp<LocalRegistrationCallback>&) {
    return INVALID_OPERATION;
}

std::vector<IServiceManager::ServiceDebugInfo> FakeServiceManager::getServiceDebugInfo() {
    std::vector<IServiceManager::ServiceDebugInfo> ret;
    return ret;
}

void FakeServiceManager::clear() {
    mNameToService.clear();
}
}  // namespace android
