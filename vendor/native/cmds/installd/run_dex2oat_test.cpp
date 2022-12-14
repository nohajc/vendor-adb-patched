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

#include <map>
#include <memory>
#include <string>

#include <android-base/logging.h>

#include <gtest/gtest.h>

#include "execv_helper.h"
#include "run_dex2oat.h"
#include "unique_file.h"

namespace android {
namespace installd {

class RunDex2OatTest : public testing::Test {
  public:
    static constexpr const char* INPUT_PATH = "/dir/input/basename.apk";
    static constexpr const char* OUTPUT_PATH = "/dir/output/basename.oat";
    static constexpr const char* FLAG_UNUSED = "{{FLAG_UNUSED}}";

    // UniqueFile closes FD. Avoid using standard I/O since the test is expected to print gtest
    // results. Alternatively, mock out UniqueFile to avoid the side effect of close(2).
    static constexpr int ZIP_FD = 3;
    static constexpr int OAT_FD = 4;
    static constexpr int INPUT_VDEX_FD = 5;
    static constexpr int OUTPUT_VDEX_FD = 6;
    static constexpr int IMAGE_FD = 7;
    static constexpr int PROFILE_FD = 8;
    static constexpr int DEX_METADATA_FD = 9;
    static constexpr int SWAP_FD = 10;

    using FakeSystemProperties = std::map<std::string, std::string>;

    // A fake RunDex2Oat that allows to override (fake) system properties and starts with none.
    class FakeRunDex2Oat : public RunDex2Oat {
      private:
        static constexpr const char* TRUE_STR = "true";
        static constexpr const char* FALSE_STR = "false";

      public:
        FakeRunDex2Oat(ExecVHelper* execv_helper, FakeSystemProperties* properties)
          : RunDex2Oat("/dir/bin/dex2oat", execv_helper), properties_(properties) { }

        virtual ~FakeRunDex2Oat() {}

        virtual std::string GetProperty(const std::string& key,
                                        const std::string& default_value) override {
            if (!properties_) {
                return default_value;
            }
            auto iter = properties_->find(key);
            if (iter == properties_->end()) {
                return default_value;
            }
            return iter->second;
        }

        virtual bool GetBoolProperty(const std::string& key, bool default_value) override {
            std::string value = GetProperty(key, "");
            if (value == "") {
                return default_value;
            }
            return value == TRUE_STR;
        }

      private:
        FakeSystemProperties* properties_;
    };

    struct RunDex2OatArgs {
        static std::unique_ptr<RunDex2OatArgs> MakeDefaultTestArgs() {
            auto args = std::make_unique<RunDex2OatArgs>();
            args->input_dex.reset(ZIP_FD, INPUT_PATH);
            args->output_oat.reset(OAT_FD, OUTPUT_PATH);
            args->input_vdex.reset(INPUT_VDEX_FD, "UNUSED_PATH");
            args->output_vdex.reset(OUTPUT_VDEX_FD, "UNUSED_PATH");
            args->instruction_set = "arm64";
            args->compilation_reason = "rundex2oattest";
            return args;
        }

        UniqueFile output_oat;
        UniqueFile output_vdex;
        UniqueFile output_image;
        UniqueFile input_dex;
        UniqueFile input_vdex;
        UniqueFile dex_metadata;
        UniqueFile profile;
        int swap_fd = -1;
        const char* instruction_set = nullptr;
        const char* compiler_filter = "extract";
        bool debuggable = false;
        bool post_bootcomplete = false;
        bool for_restore = false;
        const char* class_loader_context = nullptr;
        std::string class_loader_context_fds;
        int target_sdk_version = 0;
        bool enable_hidden_api_checks = false;
        bool generate_compact_dex = true;
        bool use_jitzygote = false;
        bool background_job_compile = false;
        const char* compilation_reason = nullptr;
    };

    class FakeExecVHelper : public ExecVHelper {
      public:
        bool HasArg(const std::string& arg) const {
            auto end = argv_.end() - 1;  // To exclude the terminating nullptr
            return find(argv_.begin(), end, arg) != end;
        }

        bool FlagNotUsed(const std::string& flag) const {
            auto has_prefix = [flag](const char* arg) {
                return strncmp(arg, flag.c_str(), flag.size()) == 0;
            };
            auto end = argv_.end() - 1;  // To exclude the terminating nullptr
            return find_if(argv_.begin(), end, has_prefix) == end;
        }

        virtual void Exec(int exit_code) override {
            std::string cmd;
            for (auto arg : argv_) {
                if (arg == nullptr) {
                  continue;
                }
                cmd += arg;
                cmd += " ";
            }
            LOG(DEBUG) << "FakeExecVHelper exit_code: " << exit_code << " cmd: " << cmd << "\n";
        }
    };

    virtual void SetUp() override {
        execv_helper_.reset(new FakeExecVHelper());
        system_properties_.clear();
        initializeDefaultExpectedFlags();
    }

    // Initializes the default flags expected to a run.  It currently matches to the expected flags
    // with RunDex2OatArgs::MakeDefaultTestArgs.
    //
    // default_expected_flags_ defines a mapping of <flag_name, expected_value>, where flag_name is
    // something like "--flag-name", and expected_value can be "=value" or ":value" (depending on
    // its delimiter), "" (if no value is needed), or a special value of FLAG_UNUSED to indicates
    // that it should not be used.
    void initializeDefaultExpectedFlags() {
        default_expected_flags_.clear();

        // Files
        default_expected_flags_["--zip-fd"] = "=" + std::to_string(ZIP_FD);
        default_expected_flags_["--zip-location"] = "=basename.apk";
        default_expected_flags_["--oat-fd"] = "=" + std::to_string(OAT_FD);
        default_expected_flags_["--oat-location"] = "=" + std::string(OUTPUT_PATH);
        default_expected_flags_["--input-vdex-fd"] = "=" + std::to_string(INPUT_VDEX_FD);
        default_expected_flags_["--output-vdex-fd"] = "=" + std::to_string(OUTPUT_VDEX_FD);
        default_expected_flags_["--classpath-dir"] = "=/dir/input";
        default_expected_flags_["--app-image-fd"] = FLAG_UNUSED;
        default_expected_flags_["--profile-file-fd"] = FLAG_UNUSED;
        default_expected_flags_["--swap-fd"] = FLAG_UNUSED;
        default_expected_flags_["--class-loader-context"] = FLAG_UNUSED;
        default_expected_flags_["--class-loader-context-fds"] = FLAG_UNUSED;
        default_expected_flags_["--boot-image"] = FLAG_UNUSED;

        // Arch
        default_expected_flags_["--instruction-set"] = "=arm64";
        default_expected_flags_["--instruction-set-features"] = FLAG_UNUSED;
        default_expected_flags_["--instruction-set-variant"] = FLAG_UNUSED;
        default_expected_flags_["--cpu-set"] = FLAG_UNUSED;

        // Misc
        default_expected_flags_["--compiler-filter"] = "=extract";
        default_expected_flags_["--compilation-reason"] = "=rundex2oattest";
        default_expected_flags_["--compact-dex-level"] = FLAG_UNUSED;
        default_expected_flags_["-j"] = FLAG_UNUSED;
        default_expected_flags_["--max-image-block-size"] = FLAG_UNUSED;
        default_expected_flags_["--very-large-app-threshold"] = FLAG_UNUSED;
        default_expected_flags_["--resolve-startup-const-strings"] = FLAG_UNUSED;
        default_expected_flags_["--force-jit-zygote"] = FLAG_UNUSED;

        // Debug
        default_expected_flags_["--debuggable"] = FLAG_UNUSED;
        default_expected_flags_["--generate-debug-info"] = FLAG_UNUSED;
        default_expected_flags_["--generate-mini-debug-info"] = FLAG_UNUSED;

        // Runtime
        // TODO(victorhsieh): Check if the previous flag is actually --runtime-arg.
        default_expected_flags_["-Xms"] = FLAG_UNUSED;
        default_expected_flags_["-Xmx"] = FLAG_UNUSED;
        default_expected_flags_["-Xbootclasspath"] = FLAG_UNUSED;
        default_expected_flags_["-Xtarget-sdk-version"] = FLAG_UNUSED;
        default_expected_flags_["-Xhidden-api-policy"] = FLAG_UNUSED;
        default_expected_flags_["-Xnorelocate"] = FLAG_UNUSED;

        // Test only
        default_expected_flags_["--foo"] = FLAG_UNUSED;
        default_expected_flags_["--bar"] = FLAG_UNUSED;
        default_expected_flags_["--baz"] = FLAG_UNUSED;
    }

    void SetExpectedFlagUsed(const std::string& flag, const std::string& value) {
        auto iter = default_expected_flags_.find(flag);
        ASSERT_NE(iter, default_expected_flags_.end()) << "Must define the default value";
        iter->second = value;
    }

    void VerifyExpectedFlags() {
        for (auto const& [flag, value] : default_expected_flags_) {
            if (value == FLAG_UNUSED) {
                EXPECT_TRUE(execv_helper_->FlagNotUsed(flag))
                    << "Flag " << flag << " should be unused, but got the value " << value;
            } else if (value == "") {
                EXPECT_TRUE(execv_helper_->HasArg(flag))
                    << "Flag " << flag << " should be specified without value, but got " << value;
            } else {
                EXPECT_TRUE(execv_helper_->HasArg(flag + value))
                    << "Flag " << flag << value << " is not specificed";
            }
        }
    }

    void setSystemProperty(const std::string& key, const std::string& value) {
        system_properties_[key] = value;
    }

    void CallRunDex2Oat(std::unique_ptr<RunDex2OatArgs> args) {
        FakeRunDex2Oat runner(execv_helper_.get(), &system_properties_);
        runner.Initialize(args->output_oat,
                          args->output_vdex,
                          args->output_image,
                          args->input_dex,
                          args->input_vdex,
                          args->dex_metadata,
                          args->profile,
                          args->class_loader_context,
                          args->class_loader_context_fds,
                          args->swap_fd,
                          args->instruction_set,
                          args->compiler_filter,
                          args->debuggable,
                          args->post_bootcomplete,
                          args->for_restore,
                          args->target_sdk_version,
                          args->enable_hidden_api_checks,
                          args->generate_compact_dex,
                          args->use_jitzygote,
                          args->background_job_compile,
                          args->compilation_reason);
        runner.Exec(/*exit_code=*/ 0);
    }

  private:
    std::unique_ptr<FakeExecVHelper> execv_helper_;
    std::map<std::string, std::string> default_expected_flags_;
    FakeSystemProperties system_properties_;
};

TEST_F(RunDex2OatTest, BasicInputOutput) {
    auto execv_helper = std::make_unique<FakeExecVHelper>();
    CallRunDex2Oat(RunDex2OatArgs::MakeDefaultTestArgs());

    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, WithAllOtherInputFds) {
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->output_image.reset(IMAGE_FD, "UNUSED_PATH");
    args->profile.reset(PROFILE_FD, "UNUSED_PATH");
    args->swap_fd = SWAP_FD;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--app-image-fd", "=" + std::to_string(IMAGE_FD));
    SetExpectedFlagUsed("--profile-file-fd", "=" + std::to_string(PROFILE_FD));
    SetExpectedFlagUsed("--swap-fd", "=" + std::to_string(SWAP_FD));
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, WithClassLoaderContext) {
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->class_loader_context = "CLASS_LOADER_CONTEXT";
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--class-loader-context", "=CLASS_LOADER_CONTEXT");
    SetExpectedFlagUsed("--class-loader-context-fds", FLAG_UNUSED);
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, WithClassLoaderContextAndFds) {
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->class_loader_context = "CLASS_LOADER_CONTEXT";
    args->class_loader_context_fds = "CLASS_LOADER_CONTEXT_FDS";
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--class-loader-context", "=CLASS_LOADER_CONTEXT");
    SetExpectedFlagUsed("--class-loader-context-fds", "=CLASS_LOADER_CONTEXT_FDS");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, WithOnlyClassLoaderContextFds) {
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->class_loader_context_fds = "CLASS_LOADER_CONTEXT_FDS";
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--class-loader-context", FLAG_UNUSED);
    SetExpectedFlagUsed("--class-loader-context-fds", FLAG_UNUSED);
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, DoNotGenerateCompactDex) {
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->generate_compact_dex = false;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--compact-dex-level", "=none");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, DoNotGenerateCompactDexWithVdexInPlaceUpdate) {
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->generate_compact_dex = true;
    args->input_vdex.reset(INPUT_VDEX_FD, "UNUSED_PATH");
    args->output_vdex.reset(INPUT_VDEX_FD, "UNUSED_PATH");
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--compact-dex-level", "=none");
    SetExpectedFlagUsed("--output-vdex-fd", "=" + std::to_string(INPUT_VDEX_FD));
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, ISA) {
    setSystemProperty("dalvik.vm.isa.x86.features", "a-x86-feature");
    setSystemProperty("dalvik.vm.isa.x86.variant", "a-x86-variant");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->instruction_set = "x86";
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--instruction-set", "=x86");
    SetExpectedFlagUsed("--instruction-set-features", "=a-x86-feature");
    SetExpectedFlagUsed("--instruction-set-variant", "=a-x86-variant");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, CpuSetPreBootComplete) {
    setSystemProperty("dalvik.vm.boot-dex2oat-cpu-set", "1,2");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = false;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--cpu-set", "=1,2");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, CpuSetPostBootCompleteNotForRestore) {
    setSystemProperty("dalvik.vm.dex2oat-cpu-set", "1,2");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = true;
    args->for_restore = false;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--cpu-set", "=1,2");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, CpuSetPostBootCompleteBackground) {
    setSystemProperty("dalvik.vm.background-dex2oat-cpu-set", "1,3");
    setSystemProperty("dalvik.vm.dex2oat-cpu-set", "1,2");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = true;
    args->background_job_compile = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--cpu-set", "=1,3");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, CpuSetPostBootCompleteBackground_Backup) {
    setSystemProperty("dalvik.vm.background-dex2oat-cpu-set", "");
    setSystemProperty("dalvik.vm.dex2oat-cpu-set", "1,2");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = true;
    args->background_job_compile = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--cpu-set", "=1,2");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, CpuSetPostBootCompleteForRestore) {
    setSystemProperty("dalvik.vm.restore-dex2oat-cpu-set", "1,2");
    setSystemProperty("dalvik.vm.dex2oat-cpu-set", "2,3");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = true;
    args->for_restore = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--cpu-set", "=1,2");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, CpuSetPostBootCompleteForRestore_Backup) {
    setSystemProperty("dalvik.vm.restore-dex2oat-cpu-set", "");
    setSystemProperty("dalvik.vm.dex2oat-cpu-set", "1,2");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = true;
    args->for_restore = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--cpu-set", "=1,2");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, Runtime) {
    setSystemProperty("dalvik.vm.dex2oat-Xms", "1234m");
    setSystemProperty("dalvik.vm.dex2oat-Xmx", "5678m");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->target_sdk_version = 30;
    args->enable_hidden_api_checks = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("-Xms", "1234m");
    SetExpectedFlagUsed("-Xmx", "5678m");
    SetExpectedFlagUsed("-Xtarget-sdk-version", ":30");
    SetExpectedFlagUsed("-Xhidden-api-policy", ":enabled");
    SetExpectedFlagUsed("-Xnorelocate", FLAG_UNUSED);
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, SkipRelocationInMinFramework) {
    setSystemProperty("vold.decrypt", "trigger_restart_min_framework");
    CallRunDex2Oat(RunDex2OatArgs::MakeDefaultTestArgs());

    SetExpectedFlagUsed("--compiler-filter", "=extract");
    SetExpectedFlagUsed("-Xnorelocate", "");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, SkipRelocationIfDecryptedWithFullDiskEncryption) {
    setSystemProperty("vold.decrypt", "1");
    CallRunDex2Oat(RunDex2OatArgs::MakeDefaultTestArgs());

    SetExpectedFlagUsed("--compiler-filter", "=extract");
    SetExpectedFlagUsed("-Xnorelocate", "");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, DalvikVmDex2oatFilter) {
    setSystemProperty("dalvik.vm.dex2oat-filter", "speed");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->compiler_filter = nullptr;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--compiler-filter", "=speed");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, ResolveStartupStartings) {
    setSystemProperty("dalvik.vm.dex2oat-resolve-startup-strings", "false");
    CallRunDex2Oat(RunDex2OatArgs::MakeDefaultTestArgs());

    SetExpectedFlagUsed("--resolve-startup-const-strings", "=false");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, ResolveStartupStartingsOverride) {
    setSystemProperty("dalvik.vm.dex2oat-resolve-startup-strings", "false");
    setSystemProperty("persist.device_config.runtime.dex2oat_resolve_startup_strings", "true");
    CallRunDex2Oat(RunDex2OatArgs::MakeDefaultTestArgs());

    SetExpectedFlagUsed("--resolve-startup-const-strings", "=true");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, ThreadsPreBootComplete) {
    setSystemProperty("dalvik.vm.boot-dex2oat-threads", "2");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = false;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("-j", "2");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, ThreadsPostBootCompleteNotForRestore) {
    setSystemProperty("dalvik.vm.dex2oat-threads", "3");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = true;
    args->for_restore = false;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("-j", "3");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, ThreadsPostBootCompleteBackground) {
    setSystemProperty("dalvik.vm.background-dex2oat-threads", "2");
    setSystemProperty("dalvik.vm.dex2oat-threads", "3");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = true;
    args->background_job_compile = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("-j", "2");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, ThreadsPostBootCompleteBackground_Backup) {
    setSystemProperty("dalvik.vm.background-dex2oat-threads", "");
    setSystemProperty("dalvik.vm.dex2oat-threads", "3");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = true;
    args->background_job_compile = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("-j", "3");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, ThreadsPostBootCompleteForRestore) {
    setSystemProperty("dalvik.vm.restore-dex2oat-threads", "4");
    setSystemProperty("dalvik.vm.dex2oat-threads", "5");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = true;
    args->for_restore = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("-j", "4");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, ThreadsPostBootCompleteForRestore_Backup) {
    setSystemProperty("dalvik.vm.restore-dex2oat-threads", "");
    setSystemProperty("dalvik.vm.dex2oat-threads", "5");
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->post_bootcomplete = true;
    args->for_restore = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("-j", "5");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, Debuggable) {
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->debuggable = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--debuggable", "");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, AlwaysDebuggable) {
    setSystemProperty("dalvik.vm.always_debuggable", "1");
    CallRunDex2Oat(RunDex2OatArgs::MakeDefaultTestArgs());

    SetExpectedFlagUsed("--debuggable", "");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, GenerateDebugInfo) {
    setSystemProperty("debug.generate-debug-info", "true");
    CallRunDex2Oat(RunDex2OatArgs::MakeDefaultTestArgs());

    SetExpectedFlagUsed("--generate-debug-info", "");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, HiddenApiCheck) {
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->enable_hidden_api_checks = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("-Xhidden-api-policy", ":enabled");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, Misc) {
    setSystemProperty("dalvik.vm.dex2oat-max-image-block-size", "524288");
    setSystemProperty("dalvik.vm.dex2oat-very-large", "100000");
    CallRunDex2Oat(RunDex2OatArgs::MakeDefaultTestArgs());

    SetExpectedFlagUsed("--max-image-block-size", "=524288");
    SetExpectedFlagUsed("--very-large-app-threshold", "=100000");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, ExtraFlags) {
    setSystemProperty("dalvik.vm.dex2oat-flags", "--foo=123 --bar:456 --baz");
    CallRunDex2Oat(RunDex2OatArgs::MakeDefaultTestArgs());

    SetExpectedFlagUsed("--foo", "=123");
    SetExpectedFlagUsed("--bar", ":456");
    SetExpectedFlagUsed("--baz", "");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, UseJitZygoteImage) {
    auto args = RunDex2OatArgs::MakeDefaultTestArgs();
    args->use_jitzygote = true;
    CallRunDex2Oat(std::move(args));

    SetExpectedFlagUsed("--force-jit-zygote", "");
    VerifyExpectedFlags();
}

TEST_F(RunDex2OatTest, BootImage) {
    setSystemProperty("dalvik.vm.boot-image", "foo.art:bar.art");
    CallRunDex2Oat(RunDex2OatArgs::MakeDefaultTestArgs());

    SetExpectedFlagUsed("--boot-image", "=foo.art:bar.art");
    VerifyExpectedFlags();
}

}  // namespace installd
}  // namespace android
