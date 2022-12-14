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

#ifndef _UI_INPUT_THREAD_H
#define _UI_INPUT_THREAD_H

#include <utils/Thread.h>

namespace android {

/* A thread that loops continuously until destructed to process input events.
 *
 * Creating the InputThread starts it immediately. The thread begins looping the loop
 * function until the InputThread is destroyed. The wake function is used to wake anything
 * that sleeps in the loop when it is time for the thread to be destroyed.
 */
class InputThread {
public:
    explicit InputThread(std::string name, std::function<void()> loop,
                         std::function<void()> wake = nullptr);
    virtual ~InputThread();

    bool isCallingThread();

private:
    std::string mName;
    std::function<void()> mThreadWake;
    sp<Thread> mThread;
};

} // namespace android

#endif // _UI_INPUT_THREAD_H