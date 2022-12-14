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

class CommandSetAmplitude : public Command {
    std::string getDescription() const override { return "Set vibration amplitude."; }

    std::string getUsageSummary() const override { return "<amplitude>"; }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
                {"<amplitude>", {"1-255."}},
        };
        return details;
    }

    Status doArgs(Args &args) override {
        if (auto amplitude = args.pop<decltype(mAmplitude)>()) {
            mAmplitude = *amplitude;
        } else {
            std::cerr << "Missing or Invalid Amplitude!" << std::endl;
            return USAGE;
        }
        if (!args.empty()) {
            std::cerr << "Unexpected Arguments!" << std::endl;
            return USAGE;
        }
        return OK;
    }

    Status doMain(Args && /*args*/) override {
        std::string statusStr;
        Status ret;

        if (auto hal = getHal<aidl::IVibrator>()) {
            auto status = hal->call(&aidl::IVibrator::setAmplitude,
                                    static_cast<float>(mAmplitude) / UINT8_MAX);
            statusStr = status.getDescription();
            ret = status.isOk() ? OK : ERROR;
        } else if (auto hal = getHal<V1_0::IVibrator>()) {
            auto status = hal->call(&V1_0::IVibrator::setAmplitude, mAmplitude);
            statusStr = toString(status);
            ret = status.isOk() && status == V1_0::Status::OK ? OK : ERROR;
        } else {
            return UNAVAILABLE;
        }

        std::cout << "Status: " << statusStr << std::endl;

        return ret;
    }

    uint8_t mAmplitude;
};

static const auto Command =
        CommandRegistry<CommandVibrator>::Register<CommandSetAmplitude>("setAmplitude");

} // namespace vibrator
} // namespace idlcli
} // namespace android
