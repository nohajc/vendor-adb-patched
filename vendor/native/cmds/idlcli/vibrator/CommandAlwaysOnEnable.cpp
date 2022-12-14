/*
 * Copyright (C) 2020 The Android Open Source Project *
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

using aidl::Effect;
using aidl::EffectStrength;

class CommandAlwaysOnEnable : public Command {
    std::string getDescription() const override {
        return "Arm always-on haptic source with an effect.";
    }

    std::string getUsageSummary() const override { return "<id> <effect> <strength>"; }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
                {"<id>", {"Source ID (device-specific)."}},
                {"<effect>", {"Effect ID."}},
                {"<strength>", {"0-2."}},
        };
        return details;
    }

    Status doArgs(Args &args) override {
        if (auto id = args.pop<decltype(mId)>()) {
            mId = *id;
            std::cout << "Source ID: " << mId << std::endl;
        } else {
            std::cerr << "Missing or Invalid Source ID!" << std::endl;
            return USAGE;
        }
        if (auto effect = args.pop<decltype(mEffect)>()) {
            mEffect = *effect;
            std::cout << "Effect: " << toString(mEffect) << std::endl;
        } else {
            std::cerr << "Missing or Invalid Effect!" << std::endl;
            return USAGE;
        }
        if (auto strength = args.pop<decltype(mStrength)>()) {
            mStrength = *strength;
            std::cout << "Strength: " << toString(mStrength) << std::endl;
        } else {
            std::cerr << "Missing or Invalid Strength!" << std::endl;
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
            auto status = hal->call(&aidl::IVibrator::alwaysOnEnable, mId, mEffect, mStrength);

            statusStr = status.getDescription();
            ret = status.isOk() ? OK : ERROR;
        } else {
            return UNAVAILABLE;
        }

        std::cout << "Status: " << statusStr << std::endl;

        return ret;
    }

    int32_t mId;
    Effect mEffect;
    EffectStrength mStrength;
};

static const auto Command =
        CommandRegistry<CommandVibrator>::Register<CommandAlwaysOnEnable>("alwaysOnEnable");

} // namespace vibrator
} // namespace idlcli
} // namespace android
