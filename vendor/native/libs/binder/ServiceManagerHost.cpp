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

#include "ServiceManagerHost.h"

#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <binder/IServiceManager.h>
#include <binder/RpcSession.h>

#include "UtilsHost.h"

namespace android {

namespace {

const void* kDeviceServiceExtraId = "DeviceServiceExtra";

// Parse stdout of program execution to string. If any error, return 0.
unsigned int parsePortNumber(const std::string& out, const std::string& what) {
    auto trimmed = android::base::Trim(out);
    unsigned int port = 0;
    if (!android::base::ParseUint(trimmed, &port)) {
        int savedErrno = errno;
        ALOGE("%s is not a valid %s: %s", trimmed.c_str(), what.c_str(), strerror(savedErrno));
        return 0;
    }
    if (port == 0) {
        ALOGE("0 is not a valid %s", what.c_str());
        return 0; // explicitly
    }
    return port;
}

// RAII object for adb forwarding
class AdbForwarder {
public:
    AdbForwarder() = default;
    static std::optional<AdbForwarder> forward(unsigned int devicePort);
    AdbForwarder(AdbForwarder&& other) noexcept { (*this) = std::move(other); }
    AdbForwarder& operator=(AdbForwarder&&) noexcept;
    ~AdbForwarder();
    [[nodiscard]] const std::optional<unsigned int>& hostPort() const { return mPort; }

private:
    DISALLOW_COPY_AND_ASSIGN(AdbForwarder);
    explicit AdbForwarder(unsigned int port) : mPort(port) {}
    std::optional<unsigned int> mPort;
};
std::optional<AdbForwarder> AdbForwarder::forward(unsigned int devicePort) {
    auto result =
            execute({"adb", "forward", "tcp:0", "tcp:" + std::to_string(devicePort)}, nullptr);
    if (!result.ok()) {
        ALOGE("Unable to run `adb forward tcp:0 tcp:%d`: %s", devicePort,
              result.error().message().c_str());
        return std::nullopt;
    }
    // Must end with exit code 0 (`has_value() && value() == 0`)
    if (result->exitCode.value_or(1) != 0) {
        ALOGE("Unable to run `adb forward tcp:0 tcp:%d`, command exits with %s", devicePort,
              result->toString().c_str());
        return std::nullopt;
    }
    if (!result->stderrStr.empty()) {
        LOG_HOST("`adb forward tcp:0 tcp:%d` writes to stderr: %s", devicePort,
                 result->stderrStr.c_str());
    }

    unsigned int hostPort = parsePortNumber(result->stdoutStr, "host port");
    if (hostPort == 0) return std::nullopt;

    return AdbForwarder(hostPort);
}

AdbForwarder& AdbForwarder::operator=(AdbForwarder&& other) noexcept {
    std::swap(mPort, other.mPort);
    return *this;
}

AdbForwarder::~AdbForwarder() {
    if (!mPort.has_value()) return;

    auto result = execute({"adb", "forward", "--remove", "tcp:" + std::to_string(*mPort)}, nullptr);
    if (!result.ok()) {
        ALOGE("Unable to run `adb forward --remove tcp:%d`: %s", *mPort,
              result.error().message().c_str());
        return;
    }
    // Must end with exit code 0 (`has_value() && value() == 0`)
    if (result->exitCode.value_or(1) != 0) {
        ALOGE("Unable to run `adb forward --remove tcp:%d`, command exits with %s", *mPort,
              result->toString().c_str());
        return;
    }
    if (!result->stderrStr.empty()) {
        LOG_HOST("`adb forward --remove tcp:%d` writes to stderr: %s", *mPort,
                 result->stderrStr.c_str());
    }

    LOG_HOST("Successfully run `adb forward --remove tcp:%d`", *mPort);
}

void cleanupCommandResult(const void* id, void* obj, void* /* cookie */) {
    LOG_ALWAYS_FATAL_IF(id != kDeviceServiceExtraId,
                        "cleanupCommandResult invoked with mismatched ID %p, "
                        "expected %p",
                        id, kDeviceServiceExtraId);
    auto ptr = static_cast<CommandResult*>(obj);
    delete ptr;
}

} // namespace

sp<IBinder> getDeviceService(std::vector<std::string>&& serviceDispatcherArgs,
                             const RpcDelegateServiceManagerOptions& options) {
    std::vector<std::string> prefix{"adb", "shell", "servicedispatcher"};
    serviceDispatcherArgs.insert(serviceDispatcherArgs.begin(), prefix.begin(), prefix.end());

    auto result = execute(std::move(serviceDispatcherArgs), &CommandResult::stdoutEndsWithNewLine);
    if (!result.ok()) {
        ALOGE("%s", result.error().message().c_str());
        return nullptr;
    }

    // `servicedispatcher` process must be alive to keep the port open.
    if (result->exitCode.has_value()) {
        ALOGE("Command exits with: %s", result->toString().c_str());
        return nullptr;
    }
    if (!result->stderrStr.empty()) {
        LOG_HOST("servicedispatcher writes to stderr: %s", result->stderrStr.c_str());
    }

    if (!result->stdoutEndsWithNewLine()) {
        ALOGE("Unexpected command result: %s", result->toString().c_str());
        return nullptr;
    }

    unsigned int devicePort = parsePortNumber(result->stdoutStr, "device port");
    if (devicePort == 0) return nullptr;

    auto forwardResult = AdbForwarder::forward(devicePort);
    if (!forwardResult.has_value()) {
        return nullptr;
    }
    LOG_ALWAYS_FATAL_IF(!forwardResult->hostPort().has_value());

    auto rpcSession = RpcSession::make();
    if (options.maxOutgoingConnections.has_value()) {
        rpcSession->setMaxOutgoingConnections(*options.maxOutgoingConnections);
    }

    if (status_t status = rpcSession->setupInetClient("127.0.0.1", *forwardResult->hostPort());
        status != OK) {
        ALOGE("Unable to set up inet client on host port %u: %s", *forwardResult->hostPort(),
              statusToString(status).c_str());
        return nullptr;
    }
    auto binder = rpcSession->getRootObject();
    if (binder == nullptr) {
        ALOGE("RpcSession::getRootObject returns nullptr");
        return nullptr;
    }

    LOG_ALWAYS_FATAL_IF(
            nullptr !=
            binder->attachObject(kDeviceServiceExtraId,
                                 static_cast<void*>(new CommandResult(std::move(*result))), nullptr,
                                 &cleanupCommandResult));
    return binder;
}

} // namespace android
