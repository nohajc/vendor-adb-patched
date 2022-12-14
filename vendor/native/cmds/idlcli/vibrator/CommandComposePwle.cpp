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

#include <stdlib.h>

#include <charconv>

#include "utils.h"
#include "vibrator.h"

namespace android {
namespace idlcli {

class CommandVibrator;

namespace vibrator {

using aidl::ActivePwle;
using aidl::Braking;
using aidl::BrakingPwle;
using aidl::PrimitivePwle;

class CommandComposePwle : public Command {
    std::string getDescription() const override { return "Compose PWLE vibration."; }

    std::string getUsageSummary() const override {
        return "[options] a <active pwle params> b <braking pwle params> ...";
    }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
            {"-b", {"Block for duration of vibration."}},
            {"a <startAmplitude> <startFrequency> <endAmplitude> <endFrequency> <duration>",
             {"Enter the active PWLE segment parameters"}},
            {"b <brakingMethod> <duration>", {"Enter the braking PWLE segment parameters"}},
            {"...", {"May repeat multiple times."}},
        };
        return details;
    }

    int getIntFromString(std::string input, int *output) {
        int rc = 0;
        int value;
        const auto res = std::from_chars(input.data(), input.data() + input.size(), value);
        if (res.ec == std::errc::invalid_argument) {
            std::cerr << "Invalid int argument: " << input << std::endl;
            rc = (int)std::errc::invalid_argument;
        } else if (res.ec == std::errc::result_out_of_range) {
            std::cerr << "Result out of range: " << input << std::endl;
            rc = (int)std::errc::result_out_of_range;
        }
        *output = value;
        return rc;
    }

    float getFloatFromString(std::string_view input, float *output) {
        int rc = 0;
        errno = 0;
        // from_chars doesn't support conversion to float so we need to first
        // convert the string_view to string and use the C-string for strtof
        float value = strtof(std::string(input).c_str(), NULL);

        if (input == "0.0" || input == "0") {
            return rc;
        }

        if (value <= 0.0) {
            std::cerr << "Invalid float argument: " << input << std::endl;
            rc = EINVAL;
        } else if (errno == ERANGE) {
            std::cerr << "Result out of range: " << input << std::endl;
            rc = errno;
        } else {
            *output = value;
        }
        return rc;
    }

    Status doArgs(Args &args) override {
        while (args.get<std::string>().value_or("").find("-") == 0) {
            auto opt = *args.pop<std::string>();
            if (opt == "--") {
                break;
            } else if (opt == "-b") {
                mBlocking = true;
            } else {
                std::cerr << "Invalid Option '" << opt << "'!" << std::endl;
                return USAGE;
            }
        }
        if (args.empty()) {
            std::cerr << "Missing arguments! Please see usage" << std::endl;
            return USAGE;
        }
        while (!args.empty()) {
            PrimitivePwle pwle;
            auto nextArg = args.pop();

            if (*nextArg == "a") {
                auto startAmplitude = args.pop();
                float startAmp;
                if (getFloatFromString(*startAmplitude, &startAmp))
                    return USAGE;

                auto startFrequency = args.pop();
                float startFreq;
                if (getFloatFromString(*startFrequency, &startFreq))
                    return USAGE;

                auto endAmplitude = args.pop();
                float endAmp;
                if (getFloatFromString(*endAmplitude, &endAmp))
                    return USAGE;

                auto endFrequency = args.pop();
                float endFreq;
                if (getFloatFromString(*endFrequency, &endFreq))
                    return USAGE;

                auto duration = args.pop();
                int dur;
                if (getIntFromString(*duration, &dur))
                    return USAGE;

                ActivePwle active = {startAmp, startFreq, endAmp, endFreq, dur};
                pwle = active;
            } else if (*nextArg == "b") {
                auto brakingMethod = args.pop();
                Braking brakingMeth;
                if (getIntFromString(*brakingMethod, (int *)&brakingMeth))
                    return USAGE;

                auto duration = args.pop();
                int dur;
                if (getIntFromString(*duration, &dur))
                    return USAGE;

                BrakingPwle braking = {brakingMeth, dur};
                pwle = braking;
            } else {
                std::cerr << "Invalid arguments! Please see usage" << std::endl;
                return USAGE;
            }
            mCompositePwle.emplace_back(std::move(pwle));
        }
        if (!args.empty()) {
            std::cerr << "Unexpected Arguments!" << std::endl;
            return USAGE;
        }
        return OK;
    }

    Status doMain(Args && /*args*/) override {
        auto hal = getHal<aidl::IVibrator>();

        if (!hal) {
            return UNAVAILABLE;
        }

        ABinderProcess_setThreadPoolMaxThreadCount(1);
        ABinderProcess_startThreadPool();

        std::shared_ptr<VibratorCallback> callback;

        if (mBlocking) {
            callback = ndk::SharedRefBase::make<VibratorCallback>();
        }

        auto status = hal->call(&aidl::IVibrator::composePwle, mCompositePwle, callback);

        if (status.isOk() && callback) {
            callback->waitForComplete();
        }

        std::cout << "Status: " << status.getDescription() << std::endl;

        return status.isOk() ? OK : ERROR;
    }

    bool mBlocking;
    std::vector<PrimitivePwle> mCompositePwle;
};

static const auto Command =
    CommandRegistry<CommandVibrator>::Register<CommandComposePwle>("composePwle");

}  // namespace vibrator
}  // namespace idlcli
}  // namespace android
