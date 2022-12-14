/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <binder/TextOutput.h>
#include <cmd.h>
#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

using namespace std;
using namespace android;

class TestTextOutput : public TextOutput {
public:
    TestTextOutput() {}
    virtual ~TestTextOutput() {}

    virtual status_t print(const char* /*txt*/, size_t /*len*/) { return NO_ERROR; }
    virtual void moveIndent(int /*delta*/) { return; }
    virtual void pushBundle() { return; }
    virtual void popBundle() { return; }
};

class CmdFuzzer {
public:
    void process(const uint8_t* data, size_t size);

private:
    FuzzedDataProvider* mFDP = nullptr;
};

void CmdFuzzer::process(const uint8_t* data, size_t size) {
    mFDP = new FuzzedDataProvider(data, size);
    vector<string> arguments;
    if (mFDP->ConsumeBool()) {
        if (mFDP->ConsumeBool()) {
            arguments = {"-w", "media.aaudio"};
        } else {
            arguments = {"-l"};
        }
    } else {
        while (mFDP->remaining_bytes() > 0) {
            size_t sizestr = mFDP->ConsumeIntegralInRange<size_t>(1, mFDP->remaining_bytes());
            string argument = mFDP->ConsumeBytesAsString(sizestr);
            arguments.emplace_back(argument);
        }
    }
    vector<string_view> argSV;
    for (auto& argument : arguments) {
        argSV.emplace_back(argument.c_str());
    }
    int32_t in = open("/dev/null", O_RDWR | O_CREAT);
    int32_t out = open("/dev/null", O_RDWR | O_CREAT);
    int32_t err = open("/dev/null", O_RDWR | O_CREAT);
    TestTextOutput output;
    TestTextOutput error;
    RunMode runMode = mFDP->ConsumeBool() ? RunMode::kStandalone : RunMode::kLibrary;
    cmdMain(argSV, output, error, in, out, err, runMode);
    delete mFDP;
    close(in);
    close(out);
    close(err);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    CmdFuzzer cmdFuzzer;
    cmdFuzzer.process(data, size);
    return 0;
}
