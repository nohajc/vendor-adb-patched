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

#ifndef FRAMEWORK_NATIVE_CMDS_IDLCLI_IDLCLI_H_
#define FRAMEWORK_NATIVE_CMDS_IDLCLI_IDLCLI_H_

#include "utils.h"

namespace android {
namespace idlcli {

class IdlCli : public CommandWithSubcommands<IdlCli> {
    std::string getDescription() const override { return "Invoke IDL APIs."; }

    std::string getUsageSummary() const override { return "<idl> [arguments]"; }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
                {"<idl>", CommandRegistry<IdlCli>::List()},
        };
        return details;
    }
};

} // namespace idlcli
} // namespace android

#endif // FRAMEWORK_NATIVE_CMDS_IDLCLI_IDLCLI_H_
