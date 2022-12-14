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

using aidl::CompositeEffect;

class CommandCompose : public Command {
    std::string getDescription() const override { return "Compose vibration."; }

    std::string getUsageSummary() const override {
        return "[options] <delay> <primitive> <scale> ...";
    }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
                {"-b", {"Block for duration of vibration."}},
                {"<delay>", {"In milliseconds"}},
                {"<primitive>", {"Primitive ID."}},
                {"<scale>", {"0.0 (inclusive) - 1.0 (inclusive)."}},
                {"...", {"May repeat multiple times."}},
        };
        return details;
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
        while (!args.empty()) {
            CompositeEffect effect;
            if (auto delay = args.pop<decltype(effect.delayMs)>()) {
                effect.delayMs = *delay;
                std::cout << "Delay: " << effect.delayMs << std::endl;
            } else {
                std::cerr << "Missing or Invalid Delay!" << std::endl;
                return USAGE;
            }
            if (auto primitive = args.pop<decltype(effect.primitive)>()) {
                effect.primitive = *primitive;
                std::cout << "Primitive: " << toString(effect.primitive) << std::endl;
            } else {
                std::cerr << "Missing or Invalid Primitive!" << std::endl;
                return USAGE;
            }
            if (auto scale = args.pop<decltype(effect.scale)>();
                scale && *scale >= 0.0 && scale <= 1.0) {
                effect.scale = *scale;
                std::cout << "Scale: " << effect.scale << std::endl;
            } else {
                std::cerr << "Missing or Invalid Scale!" << std::endl;
                return USAGE;
            }
            mComposite.emplace_back(std::move(effect));
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

        auto status = hal->call(&aidl::IVibrator::compose, mComposite, callback);

        if (status.isOk() && callback) {
            callback->waitForComplete();
        }

        std::cout << "Status: " << status.getDescription() << std::endl;

        return status.isOk() ? OK : ERROR;
    }

    bool mBlocking;
    std::vector<CompositeEffect> mComposite;
};

static const auto Command = CommandRegistry<CommandVibrator>::Register<CommandCompose>("compose");

} // namespace vibrator
} // namespace idlcli
} // namespace android
