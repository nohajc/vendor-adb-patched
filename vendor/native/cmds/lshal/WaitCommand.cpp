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

#include "WaitCommand.h"

#include "Lshal.h"

#include <hidl/ServiceManagement.h>
#include <hidl-util/FQName.h>

namespace android {
namespace lshal {

std::string WaitCommand::getName() const {
    return "wait";
}

std::string WaitCommand::getSimpleDescription() const {
    return "Wait for HIDL HAL to start if it is not already started.";
}

Status WaitCommand::parseArgs(const Arg &arg) {
    if (optind + 1 != arg.argc) {
        return USAGE;
    }

    mInterfaceName = arg.argv[optind];
    ++optind;
    return OK;
}

Status WaitCommand::main(const Arg &arg) {
    Status status = parseArgs(arg);
    if (status != OK) {
        return status;
    }

    auto [interface, instance] = splitFirst(mInterfaceName, '/');
    instance = instance.empty() ? "default" : instance;

    FQName fqName;
    if (!FQName::parse(interface, &fqName) || fqName.isIdentifier() || !fqName.isFullyQualified()) {
        mLshal.err() << "Invalid fully-qualified name '" << interface << "'\n\n";
        return USAGE;
    }

    using android::hidl::manager::V1_0::IServiceManager;

    using android::hardware::details::getRawServiceInternal;
    auto service = getRawServiceInternal(interface, instance, true /*retry*/, false /*getStub*/);

    if (service == nullptr) {
        mLshal.err() << "Service not found (missing permissions or not in VINTF manifest?).\n";
        return NO_INTERFACE;
    }

    return OK;
}

void WaitCommand::usage() const {
    static const std::string debug =
            "wait:\n"
            "    lshal wait <interface/instance> \n"
            "        For a HAL that is on the device, wait for the HAL to start.\n"
            "        This will not start a HAL unless it is configured as a lazy HAL.\n"
            "        <interface>: Format is `android.hardware.foo@1.0::IFoo/default`.\n"
            "            If instance name is missing `default` is used.\n";

    mLshal.err() << debug;
}

}  // namespace lshal
}  // namespace android

