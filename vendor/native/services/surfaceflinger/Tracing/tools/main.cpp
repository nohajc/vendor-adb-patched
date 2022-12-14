/*
 * Copyright (C) 2022 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "LayerTraceGenerator"

#include <fstream>
#include <iostream>
#include <string>

#include "LayerTraceGenerator.h"

using namespace android;

int main(int argc, char** argv) {
    if (argc > 3) {
        std::cout << "Usage: " << argv[0]
                  << " [transaction-trace-path] [output-layers-trace-path]\n";
        return -1;
    }

    const char* transactionTracePath =
            (argc > 1) ? argv[1] : "/data/misc/wmtrace/transactions_trace.winscope";
    std::cout << "Parsing " << transactionTracePath << "\n";
    std::fstream input(transactionTracePath, std::ios::in | std::ios::binary);
    if (!input) {
        std::cout << "Error: Could not open " << transactionTracePath;
        return -1;
    }

    proto::TransactionTraceFile transactionTraceFile;
    if (!transactionTraceFile.ParseFromIstream(&input)) {
        std::cout << "Error: Failed to parse " << transactionTracePath;
        return -1;
    }

    const char* outputLayersTracePath =
            (argc == 3) ? argv[2] : "/data/misc/wmtrace/layers_trace.winscope";
    ;
    ALOGD("Generating %s...", outputLayersTracePath);
    std::cout << "Generating " << outputLayersTracePath << "\n";
    if (!LayerTraceGenerator().generate(transactionTraceFile, outputLayersTracePath)) {
        std::cout << "Error: Failed to generate layers trace " << outputLayersTracePath;
        return -1;
    }
    return 0;
}