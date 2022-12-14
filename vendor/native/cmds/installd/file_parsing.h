/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef OTAPREOPT_FILE_PARSING_H_
#define OTAPREOPT_FILE_PARSING_H_

#include <fstream>
#include <functional>
#include <string_view>
#include "android-base/unique_fd.h"

namespace android {
namespace installd {

template<typename Func>
bool ParseFile(std::istream& input_stream, Func parse) {
    while (!input_stream.eof()) {
        // Read the next line.
        std::string line;
        getline(input_stream, line);

        // Is the line empty? Simplifies the next check.
        if (line.empty()) {
            continue;
        }

        // Is this a comment (starts with pound)?
        if (line[0] == '#') {
            continue;
        }

        if (!parse(line)) {
            return false;
        }
    }

    return true;
}

template<typename Func>
bool ParseFile(std::string_view str_file, Func parse) {
  std::ifstream ifs(str_file);
  if (!ifs.is_open()) {
    return false;
  }
  return ParseFile(ifs, parse);
}

}  // namespace installd
}  // namespace android

#endif  // OTAPREOPT_FILE_PARSING_H_
