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

#ifndef ANDROID_INSTALLD_EXECV_HELPER_H
#define ANDROID_INSTALLD_EXECV_HELPER_H

#include <string>
#include <vector>

namespace android {
namespace installd {

// ExecVHelper prepares and holds pointers to parsed command line arguments so that no allocations
// need to be performed between the fork and exec.
class ExecVHelper {
  public:
    ExecVHelper();
    virtual ~ExecVHelper();

    [[ noreturn ]]
    virtual void Exec(int exit_code);

    void PrepareArgs(const std::string& bin);

    // Add an arg if it's not empty.
    void AddArg(const std::string& arg);

    // Add a runtime arg if it's not empty.
    void AddRuntimeArg(const std::string& arg);

  protected:
    // Holder arrays for backing arg storage.
    std::vector<std::string> args_;

    // Argument poiners.
    std::vector<const char*> argv_;
};

}  // namespace installd
}  // namespace android

#endif  // ANDROID_INSTALLD_EXECV_HELPER_H
