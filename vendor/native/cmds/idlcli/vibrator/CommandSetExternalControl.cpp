/*
 * Copyright (C) 2019 The Android Open Source Project *
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

#include "utils.h"
#include "vibrator.h"

namespace android {
namespace idlcli {

class CommandVibrator;

namespace vibrator {

class CommandSetExternalControl : public Command {
    std::string getDescription() const override {
        return "Enable/disable vibration external control.";
    }

    std::string getUsageSummary() const override { return "<enable>"; }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
                {"<enable>", {"0/1."}},
        };
        return details;
    }

    Status doArgs(Args &args) override {
        if (auto enable = args.pop<decltype(mEnable)>()) {
            mEnable = *enable;
        } else {
            std::cerr << "Missing Enable!" << std::endl;
            return USAGE;
        }
        return OK;
    }

    Status doMain(Args && /*args*/) override {
        std::string statusStr;
        Status ret;

        if (auto hal = getHal<aidl::IVibrator>()) {
            auto status = hal->call(&aidl::IVibrator::setExternalControl, mEnable);
            statusStr = status.getDescription();
            ret = status.isOk() ? OK : ERROR;
        } else if (auto hal = getHal<V1_3::IVibrator>()) {
            auto status = hal->call(&V1_3::IVibrator::setExternalControl, mEnable);
            statusStr = toString(status);
            ret = status.isOk() && status == V1_0::Status::OK ? OK : ERROR;
        } else {
            return UNAVAILABLE;
        }

        std::cout << "Status: " << statusStr << std::endl;

        return ret;
    }

    bool mEnable;
};

static const auto Command =
        CommandRegistry<CommandVibrator>::Register<CommandSetExternalControl>("setExternalControl");

} // namespace vibrator
} // namespace idlcli
} // namespace android
