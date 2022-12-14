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

#include "log/log_main.h"
#define LOG_TAG "AidlLazyServiceRegistrar"

#include <binder/LazyServiceRegistrar.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <android/os/BnClientCallback.h>
#include <android/os/IServiceManager.h>
#include <utils/Log.h>

namespace android {
namespace binder {
namespace internal {

using AidlServiceManager = android::os::IServiceManager;

class ClientCounterCallbackImpl : public ::android::os::BnClientCallback {
public:
    ClientCounterCallbackImpl() : mNumConnectedServices(0), mForcePersist(false) {}

    bool registerService(const sp<IBinder>& service, const std::string& name,
                         bool allowIsolated, int dumpFlags);
    void forcePersist(bool persist);

    void setActiveServicesCallback(const std::function<bool(bool)>& activeServicesCallback);

    bool tryUnregisterLocked();

    void reRegisterLocked();

protected:
    Status onClients(const sp<IBinder>& service, bool clients) override;

private:
    struct Service {
        sp<IBinder> service;
        bool allowIsolated;
        int dumpFlags;

        // whether, based on onClients calls, we know we have a client for this
        // service or not
        bool clients = false;
        bool registered = true;
    };

    bool registerServiceLocked(const sp<IBinder>& service, const std::string& name,
                               bool allowIsolated, int dumpFlags);

    /**
     * Looks up a service guaranteed to be registered (service from onClients).
     */
    std::map<std::string, Service>::iterator assertRegisteredService(const sp<IBinder>& service);

    /**
     * Unregisters all services that we can. If we can't unregister all, re-register other
     * services.
     */
    void tryShutdownLocked();

    /**
     * Try to shutdown the process, unless:
     * - 'forcePersist' is 'true', or
     * - The active services count callback returns 'true', or
     * - Some services have clients.
     */
    void maybeTryShutdownLocked();

    // for below
    std::mutex mMutex;

    // count of services with clients
    size_t mNumConnectedServices;

    // previous value passed to the active services callback
    std::optional<bool> mPreviousHasClients;

    // map of registered names and services
    std::map<std::string, Service> mRegisteredServices;

    bool mForcePersist;

    // Callback used to report if there are services with clients
    std::function<bool(bool)> mActiveServicesCallback;
};

class ClientCounterCallback {
public:
    ClientCounterCallback();

    bool registerService(const sp<IBinder>& service, const std::string& name,
                                            bool allowIsolated, int dumpFlags);

    /**
     * Set a flag to prevent services from automatically shutting down
     */
    void forcePersist(bool persist);

    void setActiveServicesCallback(const std::function<bool(bool)>& activeServicesCallback);

    bool tryUnregister();

    void reRegister();

private:
    sp<ClientCounterCallbackImpl> mImpl;
};

bool ClientCounterCallbackImpl::registerService(const sp<IBinder>& service, const std::string& name,
                                            bool allowIsolated, int dumpFlags) {
    std::lock_guard<std::mutex> lock(mMutex);
    return registerServiceLocked(service, name, allowIsolated, dumpFlags);
}

bool ClientCounterCallbackImpl::registerServiceLocked(const sp<IBinder>& service,
                                                      const std::string& name, bool allowIsolated,
                                                      int dumpFlags) {
    auto manager = interface_cast<AidlServiceManager>(asBinder(defaultServiceManager()));

    bool reRegister = mRegisteredServices.count(name) > 0;
    std::string regStr = (reRegister) ? "Re-registering" : "Registering";
    ALOGI("%s service %s", regStr.c_str(), name.c_str());

    if (Status status = manager->addService(name.c_str(), service, allowIsolated, dumpFlags);
        !status.isOk()) {
        ALOGE("Failed to register service %s (%s)", name.c_str(), status.toString8().c_str());
        return false;
    }

    if (!reRegister) {
        if (Status status =
                    manager->registerClientCallback(name, service,
                                                    sp<android::os::IClientCallback>::fromExisting(
                                                            this));
            !status.isOk()) {
            ALOGE("Failed to add client callback for service %s (%s)", name.c_str(),
                  status.toString8().c_str());
            return false;
        }

        // Only add this when a service is added for the first time, as it is not removed
        mRegisteredServices[name] = {
              .service = service,
              .allowIsolated = allowIsolated,
              .dumpFlags = dumpFlags
        };
    }

    return true;
}

std::map<std::string, ClientCounterCallbackImpl::Service>::iterator ClientCounterCallbackImpl::assertRegisteredService(const sp<IBinder>& service) {
    LOG_ALWAYS_FATAL_IF(service == nullptr, "Got onClients callback for null service");
    for (auto it = mRegisteredServices.begin(); it != mRegisteredServices.end(); ++it) {
        auto const& [name, registered] = *it;
        (void) name;
        if (registered.service != service) continue;
        return it;
    }
    LOG_ALWAYS_FATAL("Got callback on service which we did not register: %s", String8(service->getInterfaceDescriptor()).c_str());
    __builtin_unreachable();
}

void ClientCounterCallbackImpl::forcePersist(bool persist) {
    std::lock_guard<std::mutex> lock(mMutex);
    mForcePersist = persist;
    if (!mForcePersist) {
        // Attempt a shutdown in case the number of clients hit 0 while the flag was on
        maybeTryShutdownLocked();
    }
}

bool ClientCounterCallbackImpl::tryUnregisterLocked() {
    auto manager = interface_cast<AidlServiceManager>(asBinder(defaultServiceManager()));

    for (auto& [name, entry] : mRegisteredServices) {
        Status status = manager->tryUnregisterService(name, entry.service);

        if (!status.isOk()) {
            ALOGI("Failed to unregister service %s (%s)", name.c_str(), status.toString8().c_str());
            return false;
        }
        entry.registered = false;
    }

    return true;
}

void ClientCounterCallbackImpl::reRegisterLocked() {
    for (auto& [name, entry] : mRegisteredServices) {
        // re-register entry if not already registered
        if (entry.registered) {
            continue;
        }

        if (!registerServiceLocked(entry.service, name, entry.allowIsolated, entry.dumpFlags)) {
            // Must restart. Otherwise, clients will never be able to get a hold of this service.
            LOG_ALWAYS_FATAL("Bad state: could not re-register services");
        }

        entry.registered = true;
    }
}

void ClientCounterCallbackImpl::maybeTryShutdownLocked() {
    if (mForcePersist) {
        ALOGI("Shutdown prevented by forcePersist override flag.");
        return;
    }

    bool handledInCallback = false;
    if (mActiveServicesCallback != nullptr) {
        bool hasClients = mNumConnectedServices != 0;
        if (hasClients != mPreviousHasClients) {
            handledInCallback = mActiveServicesCallback(hasClients);
            mPreviousHasClients = hasClients;
        }
    }

    // If there is no callback defined or the callback did not handle this
    // client count change event, try to shutdown the process if its services
    // have no clients.
    if (!handledInCallback && mNumConnectedServices == 0) {
        tryShutdownLocked();
    }
}

Status ClientCounterCallbackImpl::onClients(const sp<IBinder>& service, bool clients) {
    std::lock_guard<std::mutex> lock(mMutex);
    auto & [name, registered] = *assertRegisteredService(service);
    if (registered.clients == clients) {
        LOG_ALWAYS_FATAL("Process already thought %s had clients: %d but servicemanager has "
                         "notified has clients: %d", name.c_str(), registered.clients, clients);
    }
    registered.clients = clients;

    // update cache count of clients
    {
         size_t numWithClients = 0;
         for (const auto& [name, registered] : mRegisteredServices) {
             (void) name;
             if (registered.clients) numWithClients++;
         }
         mNumConnectedServices = numWithClients;
    }

    ALOGI("Process has %zu (of %zu available) client(s) in use after notification %s has clients: %d",
          mNumConnectedServices, mRegisteredServices.size(), name.c_str(), clients);

    maybeTryShutdownLocked();
    return Status::ok();
}

void ClientCounterCallbackImpl::tryShutdownLocked() {
    ALOGI("Trying to shut down the service. No clients in use for any service in process.");

    if (tryUnregisterLocked()) {
        ALOGI("Unregistered all clients and exiting");
        exit(EXIT_SUCCESS);
    }

    reRegisterLocked();
}

void ClientCounterCallbackImpl::setActiveServicesCallback(const std::function<bool(bool)>&
                                                          activeServicesCallback) {
    std::lock_guard<std::mutex> lock(mMutex);
    mActiveServicesCallback = activeServicesCallback;
}

ClientCounterCallback::ClientCounterCallback() {
      mImpl = sp<ClientCounterCallbackImpl>::make();
}

bool ClientCounterCallback::registerService(const sp<IBinder>& service, const std::string& name,
                                            bool allowIsolated, int dumpFlags) {
    return mImpl->registerService(service, name, allowIsolated, dumpFlags);
}

void ClientCounterCallback::forcePersist(bool persist) {
    mImpl->forcePersist(persist);
}

void ClientCounterCallback::setActiveServicesCallback(const std::function<bool(bool)>&
                                                      activeServicesCallback) {
    mImpl->setActiveServicesCallback(activeServicesCallback);
}

bool ClientCounterCallback::tryUnregister() {
    // see comments in header, this should only be called from the active
    // services callback, see also b/191781736
    return mImpl->tryUnregisterLocked();
}

void ClientCounterCallback::reRegister() {
    // see comments in header, this should only be called from the active
    // services callback, see also b/191781736
    mImpl->reRegisterLocked();
}

}  // namespace internal

LazyServiceRegistrar::LazyServiceRegistrar() {
    mClientCC = std::make_shared<internal::ClientCounterCallback>();
}

LazyServiceRegistrar& LazyServiceRegistrar::getInstance() {
    static auto registrarInstance = new LazyServiceRegistrar();
    return *registrarInstance;
}

LazyServiceRegistrar LazyServiceRegistrar::createExtraTestInstance() {
    return LazyServiceRegistrar();
}

status_t LazyServiceRegistrar::registerService(const sp<IBinder>& service, const std::string& name,
                                               bool allowIsolated, int dumpFlags) {
    if (!mClientCC->registerService(service, name, allowIsolated, dumpFlags)) {
        return UNKNOWN_ERROR;
    }
    return OK;
}

void LazyServiceRegistrar::forcePersist(bool persist) {
    mClientCC->forcePersist(persist);
}

void LazyServiceRegistrar::setActiveServicesCallback(const std::function<bool(bool)>&
                                                     activeServicesCallback) {
    mClientCC->setActiveServicesCallback(activeServicesCallback);
}

bool LazyServiceRegistrar::tryUnregister() {
    return mClientCC->tryUnregister();
}

void LazyServiceRegistrar::reRegister() {
    mClientCC->reRegister();
}

}  // namespace hardware
}  // namespace android
