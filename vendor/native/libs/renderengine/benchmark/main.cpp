/*
 * Copyright 2021 The Android Open Source Project
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

#include <RenderEngineBench.h>
#include <benchmark/benchmark.h>

int main(int argc, char** argv) {
    // Initialize will exit if it sees '--help', so check for it and print info
    // about our flags first.
    renderenginebench::parseFlagsForHelp(argc, argv);
    benchmark::Initialize(&argc, argv);

    // Calling this separately from parseFlagsForHelp prevents collisions with
    // google-benchmark's flags, since Initialize will consume and remove flags
    // it recognizes.
    renderenginebench::parseFlags(argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    return 0;
}
