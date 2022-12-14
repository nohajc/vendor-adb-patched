/*
 * Copyright (C) 2021 The Android Open Source Project *
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

class CommandGetResonantFrequency : public Command {
    std::string getDescription() const override {
        return "Retrieves vibrator resonant frequency in Hz.";
    }

    std::string getUsageSummary() const override { return ""; }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{};
        return details;
    }

    Status doArgs(Args &args) override {
        if (!args.empty()) {
            std::cerr << "Unexpected Arguments!" << std::endl;
            return USAGE;
        }
        return OK;
    }

    Status doMain(Args && /*args*/) override {
        std::string statusStr;
        float resonantFrequencyHz;
        Status ret;

        if (auto hal = getHal<aidl::IVibrator>()) {
            auto status = hal->call(&aidl::IVibrator::getResonantFrequency, &resonantFrequencyHz);
            statusStr = status.getDescription();
            ret = status.isOk() ? OK : ERROR;
        } else {
            return UNAVAILABLE;
        }

        std::cout << "Status: " << statusStr << std::endl;
        std::cout << "Resonant Frequency: " << resonantFrequencyHz << " Hz" << std::endl;

        return ret;
    }
};

static const auto Command = CommandRegistry<CommandVibrator>::Register<CommandGetResonantFrequency>(
    "getResonantFrequency");

}  // namespace vibrator
}  // namespace idlcli
}  // namespace android
