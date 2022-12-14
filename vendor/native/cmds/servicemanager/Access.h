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

#pragma once

#include <string>
#include <sys/types.h>

namespace android {

// singleton
class Access {
public:
    Access();
    virtual ~Access();

    Access(const Access&) = delete;
    Access& operator=(const Access&) = delete;
    Access(Access&&) = delete;
    Access& operator=(Access&&) = delete;

    struct CallingContext {
        pid_t debugPid;
        uid_t uid;
        std::string sid;
    };

    virtual CallingContext getCallingContext();

    virtual bool canFind(const CallingContext& ctx, const std::string& name);
    virtual bool canAdd(const CallingContext& ctx, const std::string& name);
    virtual bool canList(const CallingContext& ctx);

private:
    bool actionAllowed(const CallingContext& sctx, const char* tctx, const char* perm,
            const std::string& tname);
    bool actionAllowedFromLookup(const CallingContext& sctx, const std::string& name,
            const char *perm);

    char* mThisProcessContext = nullptr;
};

};
