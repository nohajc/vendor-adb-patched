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

    std::string getUsageSummary() const override { return "<idl> [options] [arguments]"; }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
                {"-n <name>", {"Get named service, rather than default."}},
                {"<idl>", CommandRegistry<IdlCli>::List()},
        };
        return details;
    }

    Status doArgs(Args &args) override {
        while (args.get<std::string>().value_or("").find("-") == 0) {
            auto opt = *args.pop<std::string>();
            if (opt == "--") {
                break;
            } else if (opt == "-n") {
                if (auto name = args.pop<decltype(mName)>()) {
                    mName = *name;
                } else {
                    std::cerr << "Missing Value for Name!" << std::endl;
                    return USAGE;
                }
            } else {
                std::cerr << "Invalid Option '" << opt << "'!" << std::endl;
                return USAGE;
            }
        }
        return CommandWithSubcommands::doArgs(args);
    }

    IdlCli() {}

    std::string mName;

public:
    static IdlCli &Get() {
        static IdlCli instance;
        return instance;
    }

    auto getName() { return mName; }
};

} // namespace idlcli
} // namespace android

#endif // FRAMEWORK_NATIVE_CMDS_IDLCLI_IDLCLI_H_
