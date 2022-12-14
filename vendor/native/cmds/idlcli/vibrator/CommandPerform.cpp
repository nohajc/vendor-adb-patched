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

/*
 * The following static asserts are only relevant here because the argument
 * parser uses a single implementation for determining the string names.
 */
static_assert(static_cast<uint8_t>(V1_0::EffectStrength::LIGHT) ==
              static_cast<uint8_t>(aidl::EffectStrength::LIGHT));
static_assert(static_cast<uint8_t>(V1_0::EffectStrength::MEDIUM) ==
              static_cast<uint8_t>(aidl::EffectStrength::MEDIUM));
static_assert(static_cast<uint8_t>(V1_0::EffectStrength::STRONG) ==
              static_cast<uint8_t>(aidl::EffectStrength::STRONG));
static_assert(static_cast<uint8_t>(V1_3::Effect::CLICK) ==
              static_cast<uint8_t>(aidl::Effect::CLICK));
static_assert(static_cast<uint8_t>(V1_3::Effect::DOUBLE_CLICK) ==
              static_cast<uint8_t>(aidl::Effect::DOUBLE_CLICK));
static_assert(static_cast<uint8_t>(V1_3::Effect::TICK) == static_cast<uint8_t>(aidl::Effect::TICK));
static_assert(static_cast<uint8_t>(V1_3::Effect::THUD) == static_cast<uint8_t>(aidl::Effect::THUD));
static_assert(static_cast<uint8_t>(V1_3::Effect::POP) == static_cast<uint8_t>(aidl::Effect::POP));
static_assert(static_cast<uint8_t>(V1_3::Effect::HEAVY_CLICK) ==
              static_cast<uint8_t>(aidl::Effect::HEAVY_CLICK));
static_assert(static_cast<uint8_t>(V1_3::Effect::RINGTONE_1) ==
              static_cast<uint8_t>(aidl::Effect::RINGTONE_1));
static_assert(static_cast<uint8_t>(V1_3::Effect::RINGTONE_2) ==
              static_cast<uint8_t>(aidl::Effect::RINGTONE_2));
static_assert(static_cast<uint8_t>(V1_3::Effect::RINGTONE_15) ==
              static_cast<uint8_t>(aidl::Effect::RINGTONE_15));
static_assert(static_cast<uint8_t>(V1_3::Effect::TEXTURE_TICK) ==
              static_cast<uint8_t>(aidl::Effect::TEXTURE_TICK));

using V1_0::EffectStrength;
using V1_3::Effect;

class CommandPerform : public Command {
    std::string getDescription() const override { return "Perform vibration effect."; }

    std::string getUsageSummary() const override { return "<effect> <strength>"; }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
                {"<effect>", {"Effect ID."}},
                {"<strength>", {"0-2."}},
        };
        return details;
    }

    Status doArgs(Args &args) override {
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
        uint32_t lengthMs;
        Status ret;

        if (auto hal = getHal<aidl::IVibrator>()) {
            int32_t aidlLengthMs;
            auto status =
                    hal->call(&aidl::IVibrator::perform, static_cast<aidl::Effect>(mEffect),
                              static_cast<aidl::EffectStrength>(mStrength), nullptr, &aidlLengthMs);
            statusStr = status.getDescription();
            lengthMs = static_cast<uint32_t>(aidlLengthMs);
            ret = status.isOk() ? OK : ERROR;
        } else {
            Return<void> hidlRet;
            V1_0::Status status;
            auto callback = [&status, &lengthMs](V1_0::Status retStatus, uint32_t retLengthMs) {
                status = retStatus;
                lengthMs = retLengthMs;
            };

            if (auto hal = getHal<V1_3::IVibrator>()) {
                hidlRet = hal->call(&V1_3::IVibrator::perform_1_3,
                                    static_cast<V1_3::Effect>(mEffect), mStrength, callback);
            } else if (auto hal = getHal<V1_2::IVibrator>()) {
                hidlRet = hal->call(&V1_2::IVibrator::perform_1_2,
                                    static_cast<V1_2::Effect>(mEffect), mStrength, callback);
            } else if (auto hal = getHal<V1_1::IVibrator>()) {
                hidlRet = hal->call(&V1_1::IVibrator::perform_1_1,
                                    static_cast<V1_1::Effect_1_1>(mEffect), mStrength, callback);
            } else if (auto hal = getHal<V1_0::IVibrator>()) {
                hidlRet = hal->call(&V1_0::IVibrator::perform, static_cast<V1_0::Effect>(mEffect),
                                    mStrength, callback);
            } else {
                return UNAVAILABLE;
            }

            statusStr = toString(status);
            ret = hidlRet.isOk() && status == V1_0::Status::OK ? OK : ERROR;
        }

        std::cout << "Status: " << statusStr << std::endl;
        std::cout << "Length: " << lengthMs << std::endl;

        return ret;
    }

    Effect mEffect;
    EffectStrength mStrength;
};

static const auto Command = CommandRegistry<CommandVibrator>::Register<CommandPerform>("perform");

} // namespace vibrator
} // namespace idlcli
} // namespace android
