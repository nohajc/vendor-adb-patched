/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <android/binder_manager.h>

#include "ibinder_internal.h"
#include "status_internal.h"

#include <android-base/logging.h>
#include <binder/IServiceManager.h>
#include <binder/LazyServiceRegistrar.h>

using ::android::defaultServiceManager;
using ::android::IBinder;
using ::android::IServiceManager;
using ::android::sp;
using ::android::status_t;
using ::android::statusToString;
using ::android::String16;
using ::android::String8;

binder_exception_t AServiceManager_addService(AIBinder* binder, const char* instance) {
    if (binder == nullptr || instance == nullptr) {
        return EX_ILLEGAL_ARGUMENT;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    status_t exception = sm->addService(String16(instance), binder->getBinder());
    return PruneException(exception);
}

binder_exception_t AServiceManager_addServiceWithFlags(AIBinder* binder, const char* instance,
                                                       const AServiceManager_AddServiceFlag flags) {
    if (binder == nullptr || instance == nullptr) {
        return EX_ILLEGAL_ARGUMENT;
    }

    sp<IServiceManager> sm = defaultServiceManager();

    bool allowIsolated = flags & AServiceManager_AddServiceFlag::ADD_SERVICE_ALLOW_ISOLATED;
    status_t exception = sm->addService(String16(instance), binder->getBinder(), allowIsolated);
    return PruneException(exception);
}

AIBinder* AServiceManager_checkService(const char* instance) {
    if (instance == nullptr) {
        return nullptr;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->checkService(String16(instance));

    sp<AIBinder> ret = ABpBinder::lookupOrCreateFromBinder(binder);
    AIBinder_incStrong(ret.get());
    return ret.get();
}
AIBinder* AServiceManager_getService(const char* instance) {
    if (instance == nullptr) {
        return nullptr;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16(instance));

    sp<AIBinder> ret = ABpBinder::lookupOrCreateFromBinder(binder);
    AIBinder_incStrong(ret.get());
    return ret.get();
}
binder_status_t AServiceManager_registerLazyService(AIBinder* binder, const char* instance) {
    if (binder == nullptr || instance == nullptr) {
        return STATUS_UNEXPECTED_NULL;
    }

    auto serviceRegistrar = android::binder::LazyServiceRegistrar::getInstance();
    status_t status = serviceRegistrar.registerService(binder->getBinder(), instance);

    return PruneStatusT(status);
}
AIBinder* AServiceManager_waitForService(const char* instance) {
    if (instance == nullptr) {
        return nullptr;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->waitForService(String16(instance));

    sp<AIBinder> ret = ABpBinder::lookupOrCreateFromBinder(binder);
    AIBinder_incStrong(ret.get());
    return ret.get();
}
typedef void (*AServiceManager_onRegister)(const char* instance, AIBinder* registered,
                                           void* cookie);

struct AServiceManager_NotificationRegistration
    : public IServiceManager::LocalRegistrationCallback {
    std::mutex m;
    const char* instance = nullptr;
    void* cookie = nullptr;
    AServiceManager_onRegister onRegister = nullptr;

    virtual void onServiceRegistration(const String16& smInstance, const sp<IBinder>& binder) {
        std::lock_guard<std::mutex> l(m);
        if (onRegister == nullptr) return;

        CHECK_EQ(String8(smInstance), instance);

        sp<AIBinder> ret = ABpBinder::lookupOrCreateFromBinder(binder);
        AIBinder_incStrong(ret.get());

        onRegister(instance, ret.get(), cookie);
    }

    void clear() {
        std::lock_guard<std::mutex> l(m);
        instance = nullptr;
        cookie = nullptr;
        onRegister = nullptr;
    }
};

__attribute__((warn_unused_result)) AServiceManager_NotificationRegistration*
AServiceManager_registerForServiceNotifications(const char* instance,
                                                AServiceManager_onRegister onRegister,
                                                void* cookie) {
    CHECK_NE(instance, nullptr);
    CHECK_NE(onRegister, nullptr) << instance;
    // cookie can be nullptr

    auto cb = sp<AServiceManager_NotificationRegistration>::make();
    cb->instance = instance;
    cb->onRegister = onRegister;
    cb->cookie = cookie;

    sp<IServiceManager> sm = defaultServiceManager();
    if (status_t res = sm->registerForNotifications(String16(instance), cb); res != STATUS_OK) {
        LOG(ERROR) << "Failed to register for service notifications for " << instance << ": "
                   << statusToString(res);
        return nullptr;
    }

    cb->incStrong(nullptr);
    return cb.get();
}

void AServiceManager_NotificationRegistration_delete(
        AServiceManager_NotificationRegistration* notification) {
    CHECK_NE(notification, nullptr);
    notification->clear();
    notification->decStrong(nullptr);
}

bool AServiceManager_isDeclared(const char* instance) {
    if (instance == nullptr) {
        return false;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    return sm->isDeclared(String16(instance));
}
void AServiceManager_forEachDeclaredInstance(const char* interface, void* context,
                                             void (*callback)(const char*, void*)) {
    CHECK(interface != nullptr);
    // context may be nullptr
    CHECK(callback != nullptr);

    sp<IServiceManager> sm = defaultServiceManager();
    for (const String16& instance : sm->getDeclaredInstances(String16(interface))) {
        callback(String8(instance).c_str(), context);
    }
}
bool AServiceManager_isUpdatableViaApex(const char* instance) {
    if (instance == nullptr) {
        return false;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    return sm->updatableViaApex(String16(instance)) != std::nullopt;
}
void AServiceManager_getUpdatableApexName(const char* instance, void* context,
                                          void (*callback)(const char*, void*)) {
    CHECK_NE(instance, nullptr);
    // context may be nullptr
    CHECK_NE(callback, nullptr);

    sp<IServiceManager> sm = defaultServiceManager();
    std::optional<String16> updatableViaApex = sm->updatableViaApex(String16(instance));
    if (updatableViaApex.has_value()) {
        callback(String8(updatableViaApex.value()).c_str(), context);
    }
}
void AServiceManager_forceLazyServicesPersist(bool persist) {
    auto serviceRegistrar = android::binder::LazyServiceRegistrar::getInstance();
    serviceRegistrar.forcePersist(persist);
}
void AServiceManager_setActiveServicesCallback(bool (*callback)(bool, void*), void* context) {
    auto serviceRegistrar = android::binder::LazyServiceRegistrar::getInstance();
    std::function<bool(bool)> fn = [=](bool hasClients) -> bool {
        return callback(hasClients, context);
    };
    serviceRegistrar.setActiveServicesCallback(fn);
}
bool AServiceManager_tryUnregister() {
    auto serviceRegistrar = android::binder::LazyServiceRegistrar::getInstance();
    return serviceRegistrar.tryUnregister();
}
void AServiceManager_reRegister() {
    auto serviceRegistrar = android::binder::LazyServiceRegistrar::getInstance();
    serviceRegistrar.reRegister();
}
