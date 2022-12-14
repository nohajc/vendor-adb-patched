/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef ANDROID_INPUT_FLINGER_H
#define ANDROID_INPUT_FLINGER_H

#include <stdint.h>
#include <sys/types.h>

#include "InputHost.h"

#include <android/os/BnInputFlinger.h>
#include <binder/Binder.h>
#include <cutils/compiler.h>
#include <utils/String16.h>
#include <utils/String8.h>
#include <utils/StrongPointer.h>

using android::gui::FocusRequest;
using android::os::BnInputFlinger;

namespace android {

class InputFlinger : public BnInputFlinger {
public:
    static char const* getServiceName() ANDROID_API {
        return "inputflinger";
    }

    InputFlinger() ANDROID_API;

    status_t dump(int fd, const Vector<String16>& args) override;
    binder::Status createInputChannel(const std::string&, InputChannel*) override {
        return binder::Status::ok();
    }
    binder::Status removeInputChannel(const sp<IBinder>&) override { return binder::Status::ok(); }
    binder::Status setFocusedWindow(const FocusRequest&) override { return binder::Status::ok(); }

private:
    ~InputFlinger() override;

    void dumpInternal(String8& result);

    sp<InputHostInterface> mHost;
};

} // namespace android

#endif // ANDROID_INPUT_FLINGER_H
