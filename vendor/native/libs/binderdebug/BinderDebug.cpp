/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <binder/Binder.h>
#include <sys/types.h>
#include <fstream>
#include <regex>

#include <binderdebug/BinderDebug.h>

namespace android {

static std::string contextToString(BinderDebugContext context) {
    switch (context) {
        case BinderDebugContext::BINDER:
            return "binder";
        case BinderDebugContext::HWBINDER:
            return "hwbinder";
        case BinderDebugContext::VNDBINDER:
            return "vndbinder";
        default:
            return std::string();
    }
}

static status_t scanBinderContext(pid_t pid, const std::string& contextName,
                                  std::function<void(const std::string&)> eachLine) {
    std::ifstream ifs("/dev/binderfs/binder_logs/proc/" + std::to_string(pid));
    if (!ifs.is_open()) {
        ifs.open("/d/binder/proc/" + std::to_string(pid));
        if (!ifs.is_open()) {
            return -errno;
        }
    }
    static const std::regex kContextLine("^context (\\w+)$");

    bool isDesiredContext = false;
    std::string line;
    std::smatch match;
    while (getline(ifs, line)) {
        if (std::regex_search(line, match, kContextLine)) {
            isDesiredContext = match.str(1) == contextName;
            continue;
        }
        if (!isDesiredContext) {
            continue;
        }
        eachLine(line);
    }
    return OK;
}

status_t getBinderPidInfo(BinderDebugContext context, pid_t pid, BinderPidInfo* pidInfo) {
    std::smatch match;
    static const std::regex kReferencePrefix("^\\s*node \\d+:\\s+u([0-9a-f]+)\\s+c([0-9a-f]+)\\s+");
    static const std::regex kThreadPrefix("^\\s*thread \\d+:\\s+l\\s+(\\d)(\\d)");
    std::string contextStr = contextToString(context);
    status_t ret = scanBinderContext(pid, contextStr, [&](const std::string& line) {
        if (std::regex_search(line, match, kReferencePrefix)) {
            const std::string& ptrString = "0x" + match.str(2); // use number after c
            uint64_t ptr;
            if (!::android::base::ParseUint(ptrString.c_str(), &ptr)) {
                // Should not reach here, but just be tolerant.
                return;
            }
            const std::string proc = " proc ";
            auto pos = line.rfind(proc);
            if (pos != std::string::npos) {
                for (const std::string& pidStr : base::Split(line.substr(pos + proc.size()), " ")) {
                    int32_t pid;
                    if (!::android::base::ParseInt(pidStr, &pid)) {
                        return;
                    }
                    pidInfo->refPids[ptr].push_back(pid);
                }
            }

            return;
        }
        if (std::regex_search(line, match, kThreadPrefix)) {
            // "1" is waiting in binder driver
            // "2" is poll. It's impossible to tell if these are in use.
            //     and HIDL default code doesn't use it.
            bool isInUse = match.str(1) != "1";
            // "0" is a thread that has called into binder
            // "1" is looper thread
            // "2" is main looper thread
            bool isBinderThread = match.str(2) != "0";
            if (!isBinderThread) {
                return;
            }
            if (isInUse) {
                pidInfo->threadUsage++;
            }

            pidInfo->threadCount++;
            return;
        }
        return;
    });
    return ret;
}

} // namespace  android
