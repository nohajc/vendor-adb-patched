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

#include "dump.h"

#include <iostream>
#include <string_view>

using namespace std::literals;

static void usage() {
    std::cerr << "Usage: incfsdump backing_file1 [backing_file2...]\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Bad command line: requires at least one argument\n";
        usage();
        return 1;
    }

    bool printedHelp = false;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == "--help"sv || argv[i] == "-h"sv) {
            if (std::exchange(printedHelp, true) == false) {
                usage();
            }
        }
        android::incfs::dump(argv[i]);
    }
}
