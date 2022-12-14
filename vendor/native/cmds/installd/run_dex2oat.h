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

#ifndef ANDROID_INSTALLD_RUN_DEX2OAT_H
#define ANDROID_INSTALLD_RUN_DEX2OAT_H

#include <memory>
#include <string>

#include "execv_helper.h"

namespace android {
namespace installd {

class UniqueFile;

class RunDex2Oat {
  public:
    explicit RunDex2Oat(const char* dex2oat_bin, ExecVHelper* execv_helper);
    virtual ~RunDex2Oat();

    void Initialize(const UniqueFile& output_oat,
                    const UniqueFile& output_vdex,
                    const UniqueFile& output_image,
                    const UniqueFile& input_dex,
                    const UniqueFile& input_vdex,
                    const UniqueFile& dex_metadata,
                    const UniqueFile& profile,
                    const char* class_loader_context,
                    const std::string& class_loader_context_fds,
                    int swap_fd,
                    const char* instruction_set,
                    const char* compiler_filter,
                    bool debuggable,
                    bool post_bootcomplete,
                    bool for_restore,
                    int target_sdk_version,
                    bool enable_hidden_api_checks,
                    bool generate_compact_dex,
                    bool use_jitzygote,
                    bool background_job_compile,
                    const char* compilation_reason);

    void Exec(int exit_code);

  protected:
    void PrepareBootImageFlags(bool use_jitzygote);
    void PrepareInputFileFlags(const UniqueFile& output_oat,
                               const UniqueFile& output_vdex,
                               const UniqueFile& output_image,
                               const UniqueFile& input_dex,
                               const UniqueFile& input_vdex,
                               const UniqueFile& dex_metadata,
                               const UniqueFile& profile,
                               int swap_fd,
                               const char* class_loader_context,
                               const std::string& class_loader_context_fds);
    void PrepareCompilerConfigFlags(const UniqueFile& input_vdex,
                                    const UniqueFile& output_vdex,
                                    const char* instruction_set,
                                    const char* compiler_filter,
                                    bool debuggable,
                                    int target_sdk_version,
                                    bool enable_hidden_api_checks,
                                    bool generate_compact_dex,
                                    const char* compilation_reason);
    void PrepareCompilerRuntimeAndPerfConfigFlags(bool post_bootcomplete,
                                                  bool for_restore,
                                                  bool background_job_compile);

    virtual std::string GetProperty(const std::string& key, const std::string& default_value);
    virtual bool GetBoolProperty(const std::string& key, bool default_value);

  private:
    void AddArg(const std::string& arg);
    void AddRuntimeArg(const std::string& arg);

    std::string MapPropertyToArg(const std::string& property,
                                 const std::string& format,
                                 const std::string& default_value = "");

    std::string MapPropertyToArgWithBackup(const std::string& property,
                                           const std::string& backupProperty,
                                           const std::string& format,
                                           const std::string& default_value = "");

    const std::string dex2oat_bin_;
    ExecVHelper* execv_helper_;  // not owned
};

}  // namespace installd
}  // namespace android

#endif  // ANDROID_INSTALLD_RUN_DEX2OAT_H
