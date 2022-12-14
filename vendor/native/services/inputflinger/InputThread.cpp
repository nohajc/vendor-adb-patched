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

#include "InputThread.h"

namespace android {

namespace {

// Implementation of Thread from libutils.
class InputThreadImpl : public Thread {
public:
    explicit InputThreadImpl(std::function<void()> loop)
          : Thread(/* canCallJava */ true), mThreadLoop(loop) {}

    ~InputThreadImpl() {}

private:
    std::function<void()> mThreadLoop;

    bool threadLoop() override {
        mThreadLoop();
        return true;
    }
};

} // namespace

InputThread::InputThread(std::string name, std::function<void()> loop, std::function<void()> wake)
      : mName(name), mThreadWake(wake) {
    mThread = new InputThreadImpl(loop);
    mThread->run(mName.c_str(), ANDROID_PRIORITY_URGENT_DISPLAY);
}

InputThread::~InputThread() {
    mThread->requestExit();
    if (mThreadWake) {
        mThreadWake();
    }
    mThread->requestExitAndWait();
}

bool InputThread::isCallingThread() {
    return gettid() == mThread->getTid();
}

} // namespace android