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
#define LOG_TAG "installd"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <iomanip>
#include <mutex>
#include <unordered_set>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/no_destructor.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <async_safe/log.h>
#include <cutils/fs.h>
#include <cutils/properties.h>
#include <cutils/sched_policy.h>
#include <log/log.h>               // TODO: Move everything to base/logging.
#include <openssl/sha.h>
#include <private/android_filesystem_config.h>
#include <processgroup/processgroup.h>
#include <selinux/android.h>
#include <server_configurable_flags/get_flags.h>
#include <system/thread_defs.h>
#include <utils/Mutex.h>
#include <ziparchive/zip_archive.h>

#include "dexopt.h"
#include "dexopt_return_codes.h"
#include "execv_helper.h"
#include "globals.h"
#include "installd_constants.h"
#include "installd_deps.h"
#include "otapreopt_utils.h"
#include "restorable_file.h"
#include "run_dex2oat.h"
#include "unique_file.h"
#include "utils.h"

using android::base::Basename;
using android::base::EndsWith;
using android::base::GetBoolProperty;
using android::base::GetProperty;
using android::base::ReadFdToString;
using android::base::ReadFully;
using android::base::StringPrintf;
using android::base::WriteFully;
using android::base::borrowed_fd;
using android::base::unique_fd;

namespace {

// Timeout for short operations, such as merging profiles.
constexpr int kShortTimeoutMs = 60000; // 1 minute.

// Timeout for long operations, such as compilation. This should be smaller than the Package Manager
// watchdog (PackageManagerService.WATCHDOG_TIMEOUT, 10 minutes), so that the operation will be
// aborted before that watchdog would take down the system server.
constexpr int kLongTimeoutMs = 570000; // 9.5 minutes.

class DexOptStatus {
 public:
    // Check if dexopt is cancelled and fork if it is not cancelled.
    // cancelled is set to true if cancelled. Otherwise it will be set to false.
    // If it is not cancelled, it will return the return value of fork() call.
    // If cancelled, fork will not happen and it will return -1.
    pid_t check_cancellation_and_fork(/* out */ bool *cancelled) {
        std::lock_guard<std::mutex> lock(dexopt_lock_);
        if (dexopt_blocked_) {
            *cancelled = true;
            return -1;
        }
        pid_t pid = fork();
        *cancelled = false;
        if (pid > 0) { // parent
            dexopt_pids_.insert(pid);
        }
        return pid;
    }

    // Returns true if pid was killed (is in killed list). It could have finished if killing
    // happened after the process is finished.
    bool check_if_killed_and_remove_dexopt_pid(pid_t pid) {
        std::lock_guard<std::mutex> lock(dexopt_lock_);
        dexopt_pids_.erase(pid);
        if (dexopt_killed_pids_.erase(pid) == 1) {
            return true;
        }
        return false;
    }

    // Tells whether dexopt is blocked or not.
    bool is_dexopt_blocked() {
        std::lock_guard<std::mutex> lock(dexopt_lock_);
        return dexopt_blocked_;
    }

    // Enable or disable dexopt blocking.
    void control_dexopt_blocking(bool block) {
        std::lock_guard<std::mutex> lock(dexopt_lock_);
        dexopt_blocked_ = block;
        if (!block) {
            return;
        }
        // Blocked, also kill currently running tasks
        for (auto pid : dexopt_pids_) {
            LOG(INFO) << "control_dexopt_blocking kill pid:" << pid;
            kill(pid, SIGKILL);
            dexopt_killed_pids_.insert(pid);
        }
        dexopt_pids_.clear();
    }

 private:
    std::mutex dexopt_lock_;
    // when true, dexopt is blocked and will not run.
    bool dexopt_blocked_ GUARDED_BY(dexopt_lock_) = false;
    // PIDs of child process while runinng dexopt.
    // If the child process is finished, it should be removed.
    std::unordered_set<pid_t> dexopt_pids_ GUARDED_BY(dexopt_lock_);
    // PIDs of child processes killed by cancellation.
    std::unordered_set<pid_t> dexopt_killed_pids_ GUARDED_BY(dexopt_lock_);
};

android::base::NoDestructor<DexOptStatus> dexopt_status_;

} // namespace

namespace android {
namespace installd {


// Deleter using free() for use with std::unique_ptr<>. See also UniqueCPtr<> below.
struct FreeDelete {
  // NOTE: Deleting a const object is valid but free() takes a non-const pointer.
  void operator()(const void* ptr) const {
    free(const_cast<void*>(ptr));
  }
};

// Alias for std::unique_ptr<> that uses the C function free() to delete objects.
template <typename T>
using UniqueCPtr = std::unique_ptr<T, FreeDelete>;

static unique_fd invalid_unique_fd() {
    return unique_fd(-1);
}

static bool is_debug_runtime() {
    return android::base::GetProperty("persist.sys.dalvik.vm.lib.2", "") == "libartd.so";
}

static bool is_debuggable_build() {
    return android::base::GetBoolProperty("ro.debuggable", false);
}

static bool clear_profile(const std::string& profile) {
    unique_fd ufd(open(profile.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC));
    if (ufd.get() < 0) {
        if (errno != ENOENT) {
            PLOG(WARNING) << "Could not open profile " << profile;
            return false;
        } else {
            // Nothing to clear. That's ok.
            return true;
        }
    }

    if (flock(ufd.get(), LOCK_EX | LOCK_NB) != 0) {
        if (errno != EWOULDBLOCK) {
            PLOG(WARNING) << "Error locking profile " << profile;
        }
        // This implies that the app owning this profile is running
        // (and has acquired the lock).
        //
        // If we can't acquire the lock bail out since clearing is useless anyway
        // (the app will write again to the profile).
        //
        // Note:
        // This does not impact the this is not an issue for the profiling correctness.
        // In case this is needed because of an app upgrade, profiles will still be
        // eventually cleared by the app itself due to checksum mismatch.
        // If this is needed because profman advised, then keeping the data around
        // until the next run is again not an issue.
        //
        // If the app attempts to acquire a lock while we've held one here,
        // it will simply skip the current write cycle.
        return false;
    }

    bool truncated = ftruncate(ufd.get(), 0) == 0;
    if (!truncated) {
        PLOG(WARNING) << "Could not truncate " << profile;
    }
    if (flock(ufd.get(), LOCK_UN) != 0) {
        PLOG(WARNING) << "Error unlocking profile " << profile;
    }
    return truncated;
}

// Clear the reference profile for the given location.
// The location is the profile name for primary apks or the dex path for secondary dex files.
static bool clear_reference_profile(const std::string& package_name, const std::string& location,
        bool is_secondary_dex) {
    return clear_profile(create_reference_profile_path(package_name, location, is_secondary_dex));
}

// Clear the reference profile for the given location.
// The location is the profile name for primary apks or the dex path for secondary dex files.
static bool clear_current_profile(const std::string& package_name, const std::string& location,
        userid_t user, bool is_secondary_dex) {
    return clear_profile(create_current_profile_path(user, package_name, location,
            is_secondary_dex));
}

// Clear the reference profile for the primary apk of the given package.
// The location is the profile name for primary apks or the dex path for secondary dex files.
bool clear_primary_reference_profile(const std::string& package_name,
        const std::string& location) {
    return clear_reference_profile(package_name, location, /*is_secondary_dex*/false);
}

// Clear all current profile for the primary apk of the given package.
// The location is the profile name for primary apks or the dex path for secondary dex files.
bool clear_primary_current_profiles(const std::string& package_name, const std::string& location) {
    bool success = true;
    // For secondary dex files, we don't really need the user but we use it for validity checks.
    std::vector<userid_t> users = get_known_users(/*volume_uuid*/ nullptr);
    for (auto user : users) {
        success &= clear_current_profile(package_name, location, user, /*is_secondary_dex*/false);
    }
    return success;
}

// Clear the current profile for the primary apk of the given package and user.
bool clear_primary_current_profile(const std::string& package_name, const std::string& location,
        userid_t user) {
    return clear_current_profile(package_name, location, user, /*is_secondary_dex*/false);
}

// Determines which binary we should use for execution (the debug or non-debug version).
// e.g. dex2oatd vs dex2oat
static const char* select_execution_binary(const char* binary, const char* debug_binary,
        bool background_job_compile) {
    return select_execution_binary(
        binary,
        debug_binary,
        background_job_compile,
        is_debug_runtime(),
        (android::base::GetProperty("ro.build.version.codename", "") == "REL"),
        is_debuggable_build());
}

// Determines which binary we should use for execution (the debug or non-debug version).
// e.g. dex2oatd vs dex2oat
// This is convenient method which is much easier to test because it doesn't read
// system properties.
const char* select_execution_binary(
        const char* binary,
        const char* debug_binary,
        bool background_job_compile,
        bool is_debug_runtime,
        bool is_release,
        bool is_debuggable_build) {
    // Do not use debug binaries for release candidates (to give more soak time).
    bool is_debug_bg_job = background_job_compile && is_debuggable_build && !is_release;

    // If the runtime was requested to use libartd.so, we'll run the debug version - assuming
    // the file is present (it may not be on images with very little space available).
    bool useDebug = (is_debug_runtime || is_debug_bg_job) && (access(debug_binary, X_OK) == 0);

    return useDebug ? debug_binary : binary;
}

// Namespace for Android Runtime flags applied during boot time.
static const char* RUNTIME_NATIVE_BOOT_NAMESPACE = "runtime_native_boot";
// Feature flag name for running the JIT in Zygote experiment, b/119800099.
static const char* ENABLE_JITZYGOTE_IMAGE = "enable_apex_image";

// Phenotype property name for enabling profiling the boot class path.
static const char* PROFILE_BOOT_CLASS_PATH = "profilebootclasspath";

static bool IsBootClassPathProfilingEnable() {
    std::string profile_boot_class_path = GetProperty("dalvik.vm.profilebootclasspath", "");
    profile_boot_class_path =
        server_configurable_flags::GetServerConfigurableFlag(
            RUNTIME_NATIVE_BOOT_NAMESPACE,
            PROFILE_BOOT_CLASS_PATH,
            /*default_value=*/ profile_boot_class_path);
    return profile_boot_class_path == "true";
}

/*
 * Whether dexopt should use a swap file when compiling an APK.
 *
 * If kAlwaysProvideSwapFile, do this on all devices (dex2oat will make a more informed decision
 * itself, anyways).
 *
 * Otherwise, read "dalvik.vm.dex2oat-swap". If the property exists, return whether it is "true".
 *
 * Otherwise, return true if this is a low-mem device.
 *
 * Otherwise, return default value.
 */
static bool kAlwaysProvideSwapFile = false;
static bool kDefaultProvideSwapFile = true;

static bool ShouldUseSwapFileForDexopt() {
    if (kAlwaysProvideSwapFile) {
        return true;
    }

    // Check the "override" property. If it exists, return value == "true".
    std::string dex2oat_prop_buf = GetProperty("dalvik.vm.dex2oat-swap", "");
    if (!dex2oat_prop_buf.empty()) {
        return dex2oat_prop_buf == "true";
    }

    // Shortcut for default value. This is an implementation optimization for the process sketched
    // above. If the default value is true, we can avoid to check whether this is a low-mem device,
    // as low-mem is never returning false. The compiler will optimize this away if it can.
    if (kDefaultProvideSwapFile) {
        return true;
    }

    if (GetBoolProperty("ro.config.low_ram", false)) {
        return true;
    }

    // Default value must be false here.
    return kDefaultProvideSwapFile;
}

static void SetDex2OatScheduling(bool set_to_bg) {
    if (set_to_bg) {
        if (!SetTaskProfiles(0, {"Dex2OatBootComplete"})) {
            LOG(ERROR) << "Failed to set dex2oat task profile";
            exit(DexoptReturnCodes::kSetSchedPolicy);
        }
        if (setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_BACKGROUND) < 0) {
            PLOG(ERROR) << "setpriority failed";
            exit(DexoptReturnCodes::kSetPriority);
        }
    }
}

static unique_fd create_profile(uid_t uid, const std::string& profile, int32_t flags, mode_t mode) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(profile.c_str(), flags, mode)));
    if (fd.get() < 0) {
        if (errno != EEXIST) {
            PLOG(ERROR) << "Failed to create profile " << profile;
            return invalid_unique_fd();
        }
    }
    // Profiles should belong to the app; make sure of that by giving ownership to
    // the app uid. If we cannot do that, there's no point in returning the fd
    // since dex2oat/profman will fail with SElinux denials.
    if (fchown(fd.get(), uid, uid) < 0) {
        PLOG(ERROR) << "Could not chown profile " << profile;
        return invalid_unique_fd();
    }
    return fd;
}

static unique_fd open_profile(uid_t uid, const std::string& profile, int32_t flags, mode_t mode) {
    // Do not follow symlinks when opening a profile:
    //   - primary profiles should not contain symlinks in their paths
    //   - secondary dex paths should have been already resolved and validated
    flags |= O_NOFOLLOW;

    // Check if we need to create the profile
    // Reference profiles and snapshots are created on the fly; so they might not exist beforehand.
    unique_fd fd;
    if ((flags & O_CREAT) != 0) {
        fd = create_profile(uid, profile, flags, mode);
    } else {
        fd.reset(TEMP_FAILURE_RETRY(open(profile.c_str(), flags)));
    }

    if (fd.get() < 0) {
        if (errno != ENOENT) {
            // Profiles might be missing for various reasons. For example, in a
            // multi-user environment, the profile directory for one user can be created
            // after we start a merge. In this case the current profile for that user
            // will not be found.
            // Also, the secondary dex profiles might be deleted by the app at any time,
            // so we can't we need to prepare if they are missing.
            PLOG(ERROR) << "Failed to open profile " << profile;
        }
        return invalid_unique_fd();
    } else {
        // If we just create the file we need to set its mode because on Android
        // open has a mask that only allows owner access.
        if ((flags & O_CREAT) != 0) {
            if (fchmod(fd.get(), mode) != 0) {
                PLOG(ERROR) << "Could not set mode " << std::hex << mode << std::dec
                        << " on profile" << profile;
                // Not a terminal failure.
            }
        }
    }

    return fd;
}

static unique_fd open_current_profile(uid_t uid, userid_t user, const std::string& package_name,
        const std::string& location, bool is_secondary_dex) {
    std::string profile = create_current_profile_path(user, package_name, location,
            is_secondary_dex);
    return open_profile(uid, profile, O_RDONLY, /*mode=*/ 0);
}

static unique_fd open_reference_profile(uid_t uid, const std::string& package_name,
        const std::string& location, bool read_write, bool is_secondary_dex) {
    std::string profile = create_reference_profile_path(package_name, location, is_secondary_dex);
    if (read_write && GetBoolProperty("dalvik.vm.useartservice", false)) {
        // ART Service doesn't use flock and instead assumes profile files are
        // immutable, so ensure we don't open a file for writing when it's
        // active.
        // TODO(b/251921228): Normally installd isn't called at all in that
        // case, but OTA is still an exception that uses the legacy code.
        LOG(ERROR) << "Opening ref profile " << profile
                   << " for writing is unsafe when ART Service is enabled.";
        return invalid_unique_fd();
    }
    return open_profile(
        uid,
        profile,
        read_write ? (O_CREAT | O_RDWR) : O_RDONLY,
        S_IRUSR | S_IWUSR | S_IRGRP);  // so that ART can also read it when apps run.
}

static UniqueFile open_reference_profile_as_unique_file(uid_t uid, const std::string& package_name,
                                                        const std::string& location,
                                                        bool is_secondary_dex) {
    std::string profile_path = create_reference_profile_path(package_name, location,
                                                             is_secondary_dex);
    unique_fd ufd = open_profile(uid, profile_path, O_RDONLY,
                                 S_IRUSR | S_IWUSR |
                                         S_IRGRP); // so that ART can also read it when apps run.

    return UniqueFile(ufd.release(), profile_path, [](const std::string& path) {
        clear_profile(path);
    });
}

static unique_fd open_snapshot_profile(uid_t uid, const std::string& package_name,
                                       const std::string& location) {
    std::string profile = create_snapshot_profile_path(package_name, location);
    return open_profile(uid, profile, O_CREAT | O_RDWR | O_TRUNC,  S_IRUSR | S_IWUSR);
}

static void open_profile_files(uid_t uid, const std::string& package_name,
            const std::string& location, bool is_secondary_dex,
            /*out*/ std::vector<unique_fd>* profiles_fd, /*out*/ unique_fd* reference_profile_fd) {
    // Open the reference profile in read-write mode as profman might need to save the merge.
    *reference_profile_fd = open_reference_profile(uid, package_name, location,
            /*read_write*/ true, is_secondary_dex);

    // For secondary dex files, we don't really need the user but we use it for validity checks.
    // Note: the user owning the dex file should be the current user.
    std::vector<userid_t> users;
    if (is_secondary_dex){
        users.push_back(multiuser_get_user_id(uid));
    } else {
        users = get_known_users(/*volume_uuid*/ nullptr);
    }
    for (auto user : users) {
        unique_fd profile_fd = open_current_profile(uid, user, package_name, location,
                is_secondary_dex);
        // Add to the lists only if both fds are valid.
        if (profile_fd.get() >= 0) {
            profiles_fd->push_back(std::move(profile_fd));
        }
    }
}

// Cleans up an output file specified by a file descriptor. This function should be called whenever
// a subprocess that modifies a system-managed file crashes.
// If the subprocess crashes while it's writing to the file, the file is likely corrupted, so we
// should remove it.
// If the subprocess times out and is killed while it's acquiring a flock on the file, there is
// probably a deadlock, so it's also good to remove the file so that later operations won't
// encounter the same problem. It's safe to do so because the process that is holding the flock will
// still have access to the file until the file descriptor is closed.
// Note that we can't do `clear_reference_profile` here even if the fd points to a reference profile
// because that also requires a flock and is therefore likely to be stuck in the second case.
static bool cleanup_output_fd(int fd) {
    std::string path;
    bool ret = remove_file_at_fd(fd, &path);
    if (ret) {
        LOG(INFO) << "Removed file at path " << path;
    }
    return ret;
}

static constexpr int PROFMAN_BIN_RETURN_CODE_SUCCESS = 0;
static constexpr int PROFMAN_BIN_RETURN_CODE_COMPILE = 1;
static constexpr int PROFMAN_BIN_RETURN_CODE_SKIP_COMPILATION_NOT_ENOUGH_DELTA = 2;
static constexpr int PROFMAN_BIN_RETURN_CODE_BAD_PROFILES = 3;
static constexpr int PROFMAN_BIN_RETURN_CODE_ERROR_IO = 4;
static constexpr int PROFMAN_BIN_RETURN_CODE_ERROR_LOCKING = 5;
static constexpr int PROFMAN_BIN_RETURN_CODE_ERROR_DIFFERENT_VERSIONS = 6;
static constexpr int PROFMAN_BIN_RETURN_CODE_SKIP_COMPILATION_EMPTY_PROFILES = 7;

class RunProfman : public ExecVHelper {
  public:
    template <typename T, typename U>
    void SetupArgs(const std::vector<T>& profile_fds,
                   const unique_fd& reference_profile_fd,
                   const std::vector<U>& apk_fds,
                   const std::vector<std::string>& dex_locations,
                   bool copy_and_update,
                   bool for_snapshot,
                   bool for_boot_image) {

        // TODO(calin): Assume for now we run in the bg compile job (which is in
        // most of the invocation). With the current data flow, is not very easy or
        // clean to discover this in RunProfman (it will require quite a messy refactoring).
        const char* profman_bin = select_execution_binary(
            kProfmanPath, kProfmanDebugPath, /*background_job_compile=*/ true);

        if (copy_and_update) {
            CHECK_EQ(1u, profile_fds.size());
            CHECK_EQ(1u, apk_fds.size());
        }
        if (reference_profile_fd != -1) {
            AddArg("--reference-profile-file-fd=" + std::to_string(reference_profile_fd.get()));
        }

        for (const T& fd : profile_fds) {
            AddArg("--profile-file-fd=" + std::to_string(fd.get()));
        }

        for (const U& fd : apk_fds) {
            AddArg("--apk-fd=" + std::to_string(fd.get()));
        }

        for (const std::string& dex_location : dex_locations) {
            AddArg("--dex-location=" + dex_location);
        }

        if (copy_and_update) {
            AddArg("--copy-and-update-profile-key");
        }

        if (for_snapshot) {
            AddArg("--force-merge");
        }

        if (for_boot_image) {
            AddArg("--boot-image-merge");
        }

        // The percent won't exceed 100, otherwise, don't set it and use the
        // default one set in profman.
        uint32_t min_new_classes_percent_change = ::android::base::GetUintProperty<uint32_t>(
            "dalvik.vm.bgdexopt.new-classes-percent",
            /*default*/std::numeric_limits<uint32_t>::max());
        if (min_new_classes_percent_change <= 100) {
          AddArg("--min-new-classes-percent-change=" +
                 std::to_string(min_new_classes_percent_change));
        }

        // The percent won't exceed 100, otherwise, don't set it and use the
        // default one set in profman.
        uint32_t min_new_methods_percent_change = ::android::base::GetUintProperty<uint32_t>(
            "dalvik.vm.bgdexopt.new-methods-percent",
            /*default*/std::numeric_limits<uint32_t>::max());
        if (min_new_methods_percent_change <= 100) {
          AddArg("--min-new-methods-percent-change=" +
                 std::to_string(min_new_methods_percent_change));
        }

        // Do not add after dex2oat_flags, they should override others for debugging.
        PrepareArgs(profman_bin);
    }

    void SetupMerge(const std::vector<unique_fd>& profiles_fd,
                    const unique_fd& reference_profile_fd,
                    const std::vector<unique_fd>& apk_fds = std::vector<unique_fd>(),
                    const std::vector<std::string>& dex_locations = std::vector<std::string>(),
                    bool for_snapshot = false,
                    bool for_boot_image = false) {
        SetupArgs(profiles_fd,
                  reference_profile_fd,
                  apk_fds,
                  dex_locations,
                  /*copy_and_update=*/ false,
                  for_snapshot,
                  for_boot_image);
    }

    void SetupCopyAndUpdate(const unique_fd& profile_fd,
                            const unique_fd& reference_profile_fd,
                            const unique_fd& apk_fd,
                            const std::string& dex_location) {
        SetupArgs(std::vector<borrowed_fd>{profile_fd},
                  reference_profile_fd,
                  std::vector<borrowed_fd>{apk_fd},
                  {dex_location},
                  /*copy_and_update=*/true,
                  /*for_snapshot*/false,
                  /*for_boot_image*/false);
    }

    void SetupDump(const std::vector<unique_fd>& profiles_fd, const unique_fd& reference_profile_fd,
                   const std::vector<std::string>& dex_locations,
                   const std::vector<unique_fd>& apk_fds, bool dump_classes_and_methods,
                   const unique_fd& output_fd) {
        if (dump_classes_and_methods) {
            AddArg("--dump-classes-and-methods");
        } else {
            AddArg("--dump-only");
        }
        AddArg(StringPrintf("--dump-output-to-fd=%d", output_fd.get()));
        SetupArgs(profiles_fd,
                  reference_profile_fd,
                  apk_fds,
                  dex_locations,
                  /*copy_and_update=*/false,
                  /*for_snapshot*/false,
                  /*for_boot_image*/false);
    }

    using ExecVHelper::Exec;  // To suppress -Wno-overloaded-virtual
    void Exec() {
        ExecVHelper::Exec(DexoptReturnCodes::kProfmanExec);
    }
};

static int analyze_profiles(uid_t uid, const std::string& package_name,
        const std::string& location, bool is_secondary_dex) {
    std::vector<unique_fd> profiles_fd;
    unique_fd reference_profile_fd;
    open_profile_files(uid, package_name, location, is_secondary_dex,
        &profiles_fd, &reference_profile_fd);
    if (profiles_fd.empty() || (reference_profile_fd.get() < 0)) {
        // Skip profile guided compilation because no profiles were found.
        // Or if the reference profile info couldn't be opened.
        return PROFILES_ANALYSIS_DONT_OPTIMIZE_EMPTY_PROFILES;
    }

    RunProfman profman_merge;
    const std::vector<unique_fd>& apk_fds = std::vector<unique_fd>();
    const std::vector<std::string>& dex_locations = std::vector<std::string>();
    profman_merge.SetupMerge(
            profiles_fd,
            reference_profile_fd,
            apk_fds,
            dex_locations,
            /* for_snapshot= */ false,
            IsBootClassPathProfilingEnable());
    pid_t pid = fork();
    if (pid == 0) {
        /* child -- drop privileges before continuing */
        drop_capabilities(uid);
        profman_merge.Exec();
    }
    /* parent */
    int return_code = wait_child_with_timeout(pid, kShortTimeoutMs);
    bool need_to_compile = false;
    bool empty_profiles = false;
    bool should_clear_current_profiles = false;
    bool should_clear_reference_profile = false;
    if (!WIFEXITED(return_code)) {
        LOG(WARNING) << "profman failed for location " << location << ": " << return_code;
        cleanup_output_fd(reference_profile_fd.get());
    } else {
        return_code = WEXITSTATUS(return_code);
        switch (return_code) {
            case PROFMAN_BIN_RETURN_CODE_COMPILE:
                need_to_compile = true;
                should_clear_current_profiles = true;
                should_clear_reference_profile = false;
                break;
            case PROFMAN_BIN_RETURN_CODE_SKIP_COMPILATION_NOT_ENOUGH_DELTA:
                need_to_compile = false;
                should_clear_current_profiles = false;
                should_clear_reference_profile = false;
                break;
            case PROFMAN_BIN_RETURN_CODE_SKIP_COMPILATION_EMPTY_PROFILES:
                need_to_compile = false;
                empty_profiles = true;
                should_clear_current_profiles = false;
                should_clear_reference_profile = false;
                break;
            case PROFMAN_BIN_RETURN_CODE_BAD_PROFILES:
                LOG(WARNING) << "Bad profiles for location " << location;
                need_to_compile = false;
                should_clear_current_profiles = true;
                should_clear_reference_profile = true;
                break;
            case PROFMAN_BIN_RETURN_CODE_ERROR_IO:  // fall-through
            case PROFMAN_BIN_RETURN_CODE_ERROR_LOCKING:
                // Temporary IO problem (e.g. locking). Ignore but log a warning.
                LOG(WARNING) << "IO error while reading profiles for location " << location;
                need_to_compile = false;
                should_clear_current_profiles = false;
                should_clear_reference_profile = false;
                break;
            case PROFMAN_BIN_RETURN_CODE_ERROR_DIFFERENT_VERSIONS:
                need_to_compile = false;
                should_clear_current_profiles = true;
                should_clear_reference_profile = true;
                break;
           default:
                // Unknown return code or error. Unlink profiles.
                LOG(WARNING) << "Unexpected error code while processing profiles for location "
                        << location << ": " << return_code;
                need_to_compile = false;
                should_clear_current_profiles = true;
                should_clear_reference_profile = true;
                break;
        }
    }

    if (should_clear_current_profiles) {
        if (is_secondary_dex) {
            // For secondary dex files, the owning user is the current user.
            clear_current_profile(package_name, location, multiuser_get_user_id(uid),
                    is_secondary_dex);
        } else  {
            clear_primary_current_profiles(package_name, location);
        }
    }
    if (should_clear_reference_profile) {
        clear_reference_profile(package_name, location, is_secondary_dex);
    }
    int result = 0;
    if (need_to_compile) {
        result = PROFILES_ANALYSIS_OPTIMIZE;
    } else if (empty_profiles) {
        result = PROFILES_ANALYSIS_DONT_OPTIMIZE_EMPTY_PROFILES;
    } else {
        result = PROFILES_ANALYSIS_DONT_OPTIMIZE_SMALL_DELTA;
    }
    return result;
}

// Decides if profile guided compilation is needed or not based on existing profiles.
// The analysis is done for a single profile name (which corresponds to a single code path).
//
// Returns PROFILES_ANALYSIS_OPTIMIZE if there is enough information in the current profiles
// that makes it worth to recompile the package.
// If the return value is PROFILES_ANALYSIS_OPTIMIZE all the current profiles would have been
// merged into the reference profiles accessible with open_reference_profile().
//
// Return PROFILES_ANALYSIS_DONT_OPTIMIZE_SMALL_DELTA if the package should not optimize.
// As a special case returns PROFILES_ANALYSIS_DONT_OPTIMIZE_EMPTY_PROFILES if all profiles are
// empty.
int analyze_primary_profiles(uid_t uid, const std::string& package_name,
        const std::string& profile_name) {
    return analyze_profiles(uid, package_name, profile_name, /*is_secondary_dex*/false);
}

bool dump_profiles(int32_t uid, const std::string& pkgname, const std::string& profile_name,
                   const std::string& code_path, bool dump_classes_and_methods) {
    std::vector<unique_fd> profile_fds;
    unique_fd reference_profile_fd;
    std::string out_file_name = StringPrintf("/data/misc/profman/%s-%s.txt",
        pkgname.c_str(), profile_name.c_str());

    open_profile_files(uid, pkgname, profile_name, /*is_secondary_dex*/false,
            &profile_fds, &reference_profile_fd);

    const bool has_reference_profile = (reference_profile_fd.get() != -1);
    const bool has_profiles = !profile_fds.empty();

    if (!has_reference_profile && !has_profiles) {
        LOG(ERROR)  << "profman dump: no profiles to dump for " << pkgname;
        return false;
    }

    unique_fd output_fd(open(out_file_name.c_str(),
            O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644));
    if (fchmod(output_fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) < 0) {
        LOG(ERROR) << "installd cannot chmod file for dump_profile" << out_file_name;
        return false;
    }

    std::vector<std::string> dex_locations;
    std::vector<unique_fd> apk_fds;
    unique_fd apk_fd(open(code_path.c_str(), O_RDONLY | O_NOFOLLOW));
    if (apk_fd == -1) {
        PLOG(ERROR) << "installd cannot open " << code_path.c_str();
        return false;
    }
    dex_locations.push_back(Basename(code_path));
    apk_fds.push_back(std::move(apk_fd));


    RunProfman profman_dump;
    profman_dump.SetupDump(profile_fds, reference_profile_fd, dex_locations, apk_fds,
                           dump_classes_and_methods, output_fd);
    pid_t pid = fork();
    if (pid == 0) {
        /* child -- drop privileges before continuing */
        drop_capabilities(uid);
        profman_dump.Exec();
    }
    /* parent */
    int return_code = wait_child_with_timeout(pid, kShortTimeoutMs);
    if (!WIFEXITED(return_code)) {
        LOG(WARNING) << "profman failed for package " << pkgname << ": " << return_code;
        cleanup_output_fd(output_fd.get());
        return false;
    }
    return true;
}

bool copy_system_profile(const std::string& system_profile,
        uid_t packageUid, const std::string& package_name, const std::string& profile_name) {
    unique_fd in_fd(open(system_profile.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    unique_fd out_fd(open_reference_profile(packageUid,
                     package_name,
                     profile_name,
                     /*read_write*/ true,
                     /*secondary*/ false));
    if (in_fd.get() < 0) {
        PLOG(WARNING) << "Could not open profile " << system_profile;
        return false;
    }
    if (out_fd.get() < 0) {
        PLOG(WARNING) << "Could not open profile " << package_name;
        return false;
    }

    // As a security measure we want to write the profile information with the reduced capabilities
    // of the package user id. So we fork and drop capabilities in the child.
    pid_t pid = fork();
    if (pid == 0) {
        /* child -- drop privileges before continuing */
        drop_capabilities(packageUid);

        if (flock(out_fd.get(), LOCK_EX | LOCK_NB) != 0) {
            if (errno != EWOULDBLOCK) {
                async_safe_format_log(ANDROID_LOG_WARN, LOG_TAG, "Error locking profile %s: %d",
                        package_name.c_str(), errno);
            }
            // This implies that the app owning this profile is running
            // (and has acquired the lock).
            //
            // The app never acquires the lock for the reference profiles of primary apks.
            // Only dex2oat from installd will do that. Since installd is single threaded
            // we should not see this case. Nevertheless be prepared for it.
            async_safe_format_log(ANDROID_LOG_WARN, LOG_TAG, "Failed to flock %s: %d",
                    package_name.c_str(), errno);
            return false;
        }

        bool truncated = ftruncate(out_fd.get(), 0) == 0;
        if (!truncated) {
            async_safe_format_log(ANDROID_LOG_WARN, LOG_TAG, "Could not truncate %s: %d",
                    package_name.c_str(), errno);
        }

        // Copy over data.
        static constexpr size_t kBufferSize = 4 * 1024;
        char buffer[kBufferSize];
        while (true) {
            ssize_t bytes = read(in_fd.get(), buffer, kBufferSize);
            if (bytes == 0) {
                break;
            }
            write(out_fd.get(), buffer, bytes);
        }
        if (flock(out_fd.get(), LOCK_UN) != 0) {
            async_safe_format_log(ANDROID_LOG_WARN, LOG_TAG, "Error unlocking profile %s: %d",
                    package_name.c_str(), errno);
        }
        // Use _exit since we don't want to run the global destructors in the child.
        // b/62597429
        _exit(0);
    }
    /* parent */
    int return_code = wait_child_with_timeout(pid, kShortTimeoutMs);
    if (!WIFEXITED(return_code)) {
        cleanup_output_fd(out_fd.get());
        return false;
    }
    return return_code == 0;
}

static std::string replace_file_extension(const std::string& oat_path, const std::string& new_ext) {
  // A standard dalvik-cache entry. Replace ".dex" with `new_ext`.
  if (EndsWith(oat_path, ".dex")) {
    std::string new_path = oat_path;
    new_path.replace(new_path.length() - strlen(".dex"), strlen(".dex"), new_ext);
    CHECK(EndsWith(new_path, new_ext));
    return new_path;
  }

  // An odex entry. Not that this may not be an extension, e.g., in the OTA
  // case (where the base name will have an extension for the B artifact).
  size_t odex_pos = oat_path.rfind(".odex");
  if (odex_pos != std::string::npos) {
    std::string new_path = oat_path;
    new_path.replace(odex_pos, strlen(".odex"), new_ext);
    CHECK_NE(new_path.find(new_ext), std::string::npos);
    return new_path;
  }

  // Don't know how to handle this.
  return "";
}

// Translate the given oat path to an art (app image) path. An empty string
// denotes an error.
static std::string create_image_filename(const std::string& oat_path) {
    return replace_file_extension(oat_path, ".art");
}

// Translate the given oat path to a vdex path. An empty string denotes an error.
static std::string create_vdex_filename(const std::string& oat_path) {
    return replace_file_extension(oat_path, ".vdex");
}

static int open_output_file(const char* file_name, bool recreate, int permissions) {
    int flags = O_RDWR | O_CREAT;
    if (recreate) {
        if (unlink(file_name) < 0) {
            if (errno != ENOENT) {
                PLOG(ERROR) << "open_output_file: Couldn't unlink " << file_name;
            }
        }
        flags |= O_EXCL;
    }
    return open(file_name, flags, permissions);
}

static bool set_permissions_and_ownership(
        int fd, bool is_public, int uid, const char* path, bool is_secondary_dex) {
    // Primary apks are owned by the system. Secondary dex files are owned by the app.
    int owning_uid = is_secondary_dex ? uid : AID_SYSTEM;
    if (fchmod(fd,
               S_IRUSR|S_IWUSR|S_IRGRP |
               (is_public ? S_IROTH : 0)) < 0) {
        ALOGE("installd cannot chmod '%s' during dexopt\n", path);
        return false;
    } else if (fchown(fd, owning_uid, uid) < 0) {
        ALOGE("installd cannot chown '%s' during dexopt\n", path);
        return false;
    }
    return true;
}

static bool IsOutputDalvikCache(const char* oat_dir) {
  // InstallerConnection.java (which invokes installd) transforms Java null arguments
  // into '!'. Play it safe by handling it both.
  // TODO: ensure we never get null.
  // TODO: pass a flag instead of inferring if the output is dalvik cache.
  return oat_dir == nullptr || oat_dir[0] == '!';
}

// Best-effort check whether we can fit the the path into our buffers.
// Note: the cache path will require an additional 5 bytes for ".swap", but we'll try to run
// without a swap file, if necessary. Reference profiles file also add an extra ".prof"
// extension to the cache path (5 bytes).
// TODO(calin): move away from char* buffers and PKG_PATH_MAX.
static bool validate_dex_path_size(const std::string& dex_path) {
    if (dex_path.size() >= (PKG_PATH_MAX - 8)) {
        LOG(ERROR) << "dex_path too long: " << dex_path;
        return false;
    }
    return true;
}

static bool create_oat_out_path(const char* apk_path, const char* instruction_set,
            const char* oat_dir, bool is_secondary_dex, /*out*/ char* out_oat_path) {
    if (!validate_dex_path_size(apk_path)) {
        return false;
    }

    if (!IsOutputDalvikCache(oat_dir)) {
        // Oat dirs for secondary dex files are already validated.
        if (!is_secondary_dex && validate_apk_path(oat_dir)) {
            ALOGE("cannot validate apk path with oat_dir '%s'\n", oat_dir);
            return false;
        }
        if (!calculate_oat_file_path(out_oat_path, oat_dir, apk_path, instruction_set)) {
            return false;
        }
    } else {
        if (!create_cache_path(out_oat_path, apk_path, instruction_set)) {
            return false;
        }
    }
    return true;
}

// (re)Creates the app image if needed.
RestorableFile maybe_open_app_image(const std::string& out_oat_path, bool generate_app_image,
                                    bool is_public, int uid, bool is_secondary_dex) {
    const std::string image_path = create_image_filename(out_oat_path);
    if (image_path.empty()) {
        // Happens when the out_oat_path has an unknown extension.
        return RestorableFile();
    }

    // Not enabled, exit.
    if (!generate_app_image) {
        RestorableFile::RemoveAllFiles(image_path);
        return RestorableFile();
    }
    std::string app_image_format = GetProperty("dalvik.vm.appimageformat", "");
    if (app_image_format.empty()) {
        RestorableFile::RemoveAllFiles(image_path);
        return RestorableFile();
    }
    // If the app is already running and we modify the image file, it can cause crashes
    // (b/27493510).
    RestorableFile image_file = RestorableFile::CreateWritableFile(image_path,
                                                                   /*permissions*/ 0600);
    if (image_file.fd() < 0) {
        // Could not create application image file. Go on since we can compile without it.
        LOG(ERROR) << "installd could not create '" << image_path
                << "' for image file during dexopt";
        // If we have a valid image file path but cannot create tmp file, reset it.
        image_file.reset();
    } else if (!set_permissions_and_ownership(
                image_file.fd(), is_public, uid, image_path.c_str(), is_secondary_dex)) {
        ALOGE("installd cannot set owner '%s' for image during dexopt\n", image_path.c_str());
        image_file.reset();
    }

    return image_file;
}

// Creates the dexopt swap file if necessary and return its fd.
// Returns -1 if there's no need for a swap or in case of errors.
unique_fd maybe_open_dexopt_swap_file(const std::string& out_oat_path) {
    if (!ShouldUseSwapFileForDexopt()) {
        return invalid_unique_fd();
    }
    auto swap_file_name = out_oat_path + ".swap";
    unique_fd swap_fd(open_output_file(
            swap_file_name.c_str(), /*recreate*/true, /*permissions*/0600));
    if (swap_fd.get() < 0) {
        // Could not create swap file. Optimistically go on and hope that we can compile
        // without it.
        ALOGE("installd could not create '%s' for swap during dexopt\n", swap_file_name.c_str());
    } else {
        // Immediately unlink. We don't really want to hit flash.
        if (unlink(swap_file_name.c_str()) < 0) {
            PLOG(ERROR) << "Couldn't unlink swap file " << swap_file_name;
        }
    }
    return swap_fd;
}

// Opens the reference profiles if needed.
// Note that the reference profile might not exist so it's OK if the fd will be -1.
UniqueFile maybe_open_reference_profile(const std::string& pkgname,
        const std::string& dex_path, const char* profile_name, bool profile_guided,
        bool is_public, int uid, bool is_secondary_dex) {
    // If we are not profile guided compilation, or we are compiling system server
    // do not bother to open the profiles; we won't be using them.
    if (!profile_guided || (pkgname[0] == '*')) {
        return UniqueFile();
    }

    // If this is a secondary dex path which is public do not open the profile.
    // We cannot compile public secondary dex paths with profiles. That's because
    // it will expose how the dex files are used by their owner.
    //
    // Note that the PackageManager is responsible to set the is_public flag for
    // primary apks and we do not check it here. In some cases, e.g. when
    // compiling with a public profile from the .dm file the PackageManager will
    // set is_public toghether with the profile guided compilation.
    if (is_secondary_dex && is_public) {
        return UniqueFile();
    }

    // Open reference profile in read only mode as dex2oat does not get write permissions.
    std::string location;
    if (is_secondary_dex) {
        location = dex_path;
    } else {
        if (profile_name == nullptr) {
            // This path is taken for system server re-compilation lunched from ZygoteInit.
            return UniqueFile();
        } else {
            location = profile_name;
        }
    }
    return open_reference_profile_as_unique_file(uid, pkgname, location, is_secondary_dex);
}

// Opens the vdex files and assigns the input fd to in_vdex_wrapper and the output fd to
// out_vdex_wrapper. Returns true for success or false in case of errors.
bool open_vdex_files_for_dex2oat(const char* apk_path, const char* out_oat_path, int dexopt_needed,
                                 const char* instruction_set, bool is_public, int uid,
                                 bool is_secondary_dex, bool profile_guided,
                                 UniqueFile* in_vdex_wrapper, RestorableFile* out_vdex_wrapper) {
    CHECK(in_vdex_wrapper != nullptr);
    CHECK(out_vdex_wrapper != nullptr);
    // Open the existing VDEX. We do this before creating the new output VDEX, which will
    // unlink the old one.
    char in_odex_path[PKG_PATH_MAX];
    int dexopt_action = abs(dexopt_needed);
    bool is_odex_location = dexopt_needed < 0;

    // Infer the name of the output VDEX.
    const std::string out_vdex_path_str = create_vdex_filename(out_oat_path);
    if (out_vdex_path_str.empty()) {
        return false;
    }

    // Create work file first. All files will be deleted when it fails.
    *out_vdex_wrapper = RestorableFile::CreateWritableFile(out_vdex_path_str,
                                                           /*permissions*/ 0644);
    if (out_vdex_wrapper->fd() < 0) {
        ALOGE("installd cannot open vdex '%s' during dexopt\n", out_vdex_path_str.c_str());
        return false;
    }

    bool update_vdex_in_place = false;
    if (dexopt_action != DEX2OAT_FROM_SCRATCH) {
        // Open the possibly existing vdex. If none exist, we pass -1 to dex2oat for input-vdex-fd.
        const char* path = nullptr;
        if (is_odex_location) {
            if (calculate_odex_file_path(in_odex_path, apk_path, instruction_set)) {
                path = in_odex_path;
            } else {
                ALOGE("installd cannot compute input vdex location for '%s'\n", apk_path);
                return false;
            }
        } else {
            path = out_oat_path;
        }
        std::string in_vdex_path_str = create_vdex_filename(path);
        if (in_vdex_path_str.empty()) {
            ALOGE("installd cannot compute input vdex location for '%s'\n", path);
            return false;
        }
        // We can update in place when all these conditions are met:
        // 1) The vdex location to write to is the same as the vdex location to read (vdex files
        //    on /system typically cannot be updated in place).
        // 2) We dex2oat due to boot image change, because we then know the existing vdex file
        //    cannot be currently used by a running process.
        // 3) We are not doing a profile guided compilation, because dexlayout requires two
        //    different vdex files to operate.
        update_vdex_in_place =
            (in_vdex_path_str == out_vdex_path_str) &&
            (dexopt_action == DEX2OAT_FOR_BOOT_IMAGE) &&
            !profile_guided;
        if (update_vdex_in_place) {
            // dex2oat marks it invalid anyway. So delete it and set work file fd.
            unlink(in_vdex_path_str.c_str());
            // Open the file read-write to be able to update it.
            in_vdex_wrapper->reset(out_vdex_wrapper->fd(), in_vdex_path_str);
            // Disable auto close for the in wrapper fd (it will be done when destructing the out
            // wrapper).
            in_vdex_wrapper->DisableAutoClose();
        } else {
            in_vdex_wrapper->reset(open(in_vdex_path_str.c_str(), O_RDONLY, 0),
                                   in_vdex_path_str);
        }
    }

    if (!set_permissions_and_ownership(out_vdex_wrapper->fd(), is_public, uid,
            out_vdex_path_str.c_str(), is_secondary_dex)) {
        ALOGE("installd cannot set owner '%s' for vdex during dexopt\n", out_vdex_path_str.c_str());
        return false;
    }

    // If we got here we successfully opened the vdex files.
    return true;
}

// Opens the output oat file for the given apk.
RestorableFile open_oat_out_file(const char* apk_path, const char* oat_dir, bool is_public, int uid,
                                 const char* instruction_set, bool is_secondary_dex) {
    char out_oat_path[PKG_PATH_MAX];
    if (!create_oat_out_path(apk_path, instruction_set, oat_dir, is_secondary_dex, out_oat_path)) {
        return RestorableFile();
    }
    RestorableFile oat = RestorableFile::CreateWritableFile(out_oat_path, /*permissions*/ 0644);
    if (oat.fd() < 0) {
        PLOG(ERROR) << "installd cannot open output during dexopt" <<  out_oat_path;
    } else if (!set_permissions_and_ownership(
                oat.fd(), is_public, uid, out_oat_path, is_secondary_dex)) {
        ALOGE("installd cannot set owner '%s' for output during dexopt\n", out_oat_path);
        oat.reset();
    }
    return oat;
}

// Creates RDONLY fds for oat and vdex files, if exist.
// Returns false if it fails to create oat out path for the given apk path.
// Note that the method returns true even if the files could not be opened.
bool maybe_open_oat_and_vdex_file(const std::string& apk_path,
                                  const std::string& oat_dir,
                                  const std::string& instruction_set,
                                  bool is_secondary_dex,
                                  unique_fd* oat_file_fd,
                                  unique_fd* vdex_file_fd) {
    char oat_path[PKG_PATH_MAX];
    if (!create_oat_out_path(apk_path.c_str(),
                             instruction_set.c_str(),
                             oat_dir.c_str(),
                             is_secondary_dex,
                             oat_path)) {
        LOG(ERROR) << "Could not create oat out path for "
                << apk_path << " with oat dir " << oat_dir;
        return false;
    }
    oat_file_fd->reset(open(oat_path, O_RDONLY));
    if (oat_file_fd->get() < 0) {
        PLOG(INFO) << "installd cannot open oat file during dexopt" <<  oat_path;
    }

    std::string vdex_filename = create_vdex_filename(oat_path);
    vdex_file_fd->reset(open(vdex_filename.c_str(), O_RDONLY));
    if (vdex_file_fd->get() < 0) {
        PLOG(INFO) << "installd cannot open vdex file during dexopt" <<  vdex_filename;
    }

    return true;
}

// Runs (execv) dexoptanalyzer on the given arguments.
// The analyzer will check if the dex_file needs to be (re)compiled to match the compiler_filter.
// If this is for a profile guided compilation, profile_was_updated will tell whether or not
// the profile has changed.
class RunDexoptAnalyzer : public ExecVHelper {
 public:
    RunDexoptAnalyzer(const std::string& dex_file,
                      int vdex_fd,
                      int oat_fd,
                      int zip_fd,
                      const std::string& instruction_set,
                      const std::string& compiler_filter,
                      int profile_analysis_result,
                      bool downgrade,
                      const char* class_loader_context,
                      const std::string& class_loader_context_fds) {
        CHECK_GE(zip_fd, 0);

        // We always run the analyzer in the background job.
        const char* dexoptanalyzer_bin = select_execution_binary(
             kDexoptanalyzerPath, kDexoptanalyzerDebugPath, /*background_job_compile=*/ true);

        std::string dex_file_arg = "--dex-file=" + dex_file;
        std::string oat_fd_arg = "--oat-fd=" + std::to_string(oat_fd);
        std::string vdex_fd_arg = "--vdex-fd=" + std::to_string(vdex_fd);
        std::string zip_fd_arg = "--zip-fd=" + std::to_string(zip_fd);
        std::string isa_arg = "--isa=" + instruction_set;
        std::string compiler_filter_arg = "--compiler-filter=" + compiler_filter;
        std::string profile_analysis_arg = "--profile-analysis-result="
                + std::to_string(profile_analysis_result);
        const char* downgrade_flag = "--downgrade";
        std::string class_loader_context_arg = "--class-loader-context=";
        if (class_loader_context != nullptr) {
            class_loader_context_arg += class_loader_context;
        }
        std::string class_loader_context_fds_arg = "--class-loader-context-fds=";
        if (!class_loader_context_fds.empty()) {
            class_loader_context_fds_arg += class_loader_context_fds;
        }

        // program name, dex file, isa, filter
        AddArg(dex_file_arg);
        AddArg(isa_arg);
        AddArg(compiler_filter_arg);
        if (oat_fd >= 0) {
            AddArg(oat_fd_arg);
        }
        if (vdex_fd >= 0) {
            AddArg(vdex_fd_arg);
        }
        AddArg(zip_fd_arg);
        AddArg(profile_analysis_arg);

        if (downgrade) {
            AddArg(downgrade_flag);
        }
        if (class_loader_context != nullptr) {
            AddArg(class_loader_context_arg);
            if (!class_loader_context_fds.empty()) {
                AddArg(class_loader_context_fds_arg);
            }
        }

        // On-device signing related. odsign sets the system property odsign.verification.success if
        // AOT artifacts have the expected signatures.
        const bool trust_art_apex_data_files =
                ::android::base::GetBoolProperty("odsign.verification.success", false);
        if (!trust_art_apex_data_files) {
            AddRuntimeArg("-Xdeny-art-apex-data-files");
        }

        PrepareArgs(dexoptanalyzer_bin);
    }

    // Dexoptanalyzer mode which flattens the given class loader context and
    // prints a list of its dex files in that flattened order.
    RunDexoptAnalyzer(const char* class_loader_context) {
        CHECK(class_loader_context != nullptr);

        // We always run the analyzer in the background job.
        const char* dexoptanalyzer_bin = select_execution_binary(
             kDexoptanalyzerPath, kDexoptanalyzerDebugPath, /*background_job_compile=*/ true);

        AddArg("--flatten-class-loader-context");
        AddArg(std::string("--class-loader-context=") + class_loader_context);
        PrepareArgs(dexoptanalyzer_bin);
    }
};

// Prepares the oat dir for the secondary dex files.
static bool prepare_secondary_dex_oat_dir(const std::string& dex_path, int uid,
        const char* instruction_set) {
    unsigned long dirIndex = dex_path.rfind('/');
    if (dirIndex == std::string::npos) {
        LOG(ERROR ) << "Unexpected dir structure for secondary dex " << dex_path;
        return false;
    }
    std::string dex_dir = dex_path.substr(0, dirIndex);

    // Create oat file output directory.
    mode_t oat_dir_mode = S_IRWXU | S_IRWXG | S_IXOTH;
    if (prepare_app_cache_dir(dex_dir, "oat", oat_dir_mode, uid, uid) != 0) {
        LOG(ERROR) << "Could not prepare oat dir for secondary dex: " << dex_path;
        return false;
    }

    char oat_dir[PKG_PATH_MAX];
    snprintf(oat_dir, PKG_PATH_MAX, "%s/oat", dex_dir.c_str());

    if (prepare_app_cache_dir(oat_dir, instruction_set, oat_dir_mode, uid, uid) != 0) {
        LOG(ERROR) << "Could not prepare oat/isa dir for secondary dex: " << dex_path;
        return false;
    }

    return true;
}

// Return codes for identifying the reason why dexoptanalyzer was not invoked when processing
// secondary dex files. This return codes are returned by the child process created for
// analyzing secondary dex files in process_secondary_dex_dexopt.

enum DexoptAnalyzerSkipCodes {
  // The dexoptanalyzer was not invoked because of validation or IO errors.
  // Specific errors are encoded in the name.
  kSecondaryDexDexoptAnalyzerSkippedValidatePath = 200,
  kSecondaryDexDexoptAnalyzerSkippedOpenZip = 201,
  kSecondaryDexDexoptAnalyzerSkippedPrepareDir = 202,
  kSecondaryDexDexoptAnalyzerSkippedOpenOutput = 203,
  kSecondaryDexDexoptAnalyzerSkippedFailExec = 204,
  // The dexoptanalyzer was not invoked because the dex file does not exist anymore.
  kSecondaryDexDexoptAnalyzerSkippedNoFile = 205,
};

// Verifies the result of analyzing secondary dex files from process_secondary_dex_dexopt.
// If the result is valid returns true and sets dexopt_needed_out to a valid value.
// Returns false for errors or unexpected result values.
// The result is expected to be either one of SECONDARY_DEX_* codes or a valid exit code
// of dexoptanalyzer.
static bool process_secondary_dexoptanalyzer_result(const std::string& dex_path, int result,
            int* dexopt_needed_out, std::string* error_msg) {
    // The result values are defined in dexoptanalyzer.
    switch (result) {
        case 0:  // dexoptanalyzer: no_dexopt_needed
            *dexopt_needed_out = NO_DEXOPT_NEEDED; return true;
        case 1:  // dexoptanalyzer: dex2oat_from_scratch
            *dexopt_needed_out = DEX2OAT_FROM_SCRATCH; return true;
        case 4:  // dexoptanalyzer: dex2oat_for_bootimage_odex
            *dexopt_needed_out = -DEX2OAT_FOR_BOOT_IMAGE; return true;
        case 5:  // dexoptanalyzer: dex2oat_for_filter_odex
            *dexopt_needed_out = -DEX2OAT_FOR_FILTER; return true;
        case 2:  // dexoptanalyzer: dex2oat_for_bootimage_oat
        case 3:  // dexoptanalyzer: dex2oat_for_filter_oat
            *error_msg = StringPrintf("Dexoptanalyzer return the status of an oat file."
                                      " Expected odex file status for secondary dex %s"
                                      " : dexoptanalyzer result=%d",
                                      dex_path.c_str(),
                                      result);
            return false;
    }

    // Use a second switch for enum switch-case analysis.
    switch (static_cast<DexoptAnalyzerSkipCodes>(result)) {
        case kSecondaryDexDexoptAnalyzerSkippedNoFile:
            // If the file does not exist there's no need for dexopt.
            *dexopt_needed_out = NO_DEXOPT_NEEDED;
            return true;

        case kSecondaryDexDexoptAnalyzerSkippedValidatePath:
            *error_msg = "Dexoptanalyzer path validation failed";
            return false;
        case kSecondaryDexDexoptAnalyzerSkippedOpenZip:
            *error_msg = "Dexoptanalyzer open zip failed";
            return false;
        case kSecondaryDexDexoptAnalyzerSkippedPrepareDir:
            *error_msg = "Dexoptanalyzer dir preparation failed";
            return false;
        case kSecondaryDexDexoptAnalyzerSkippedOpenOutput:
            *error_msg = "Dexoptanalyzer open output failed";
            return false;
        case kSecondaryDexDexoptAnalyzerSkippedFailExec:
            *error_msg = "Dexoptanalyzer failed to execute";
            return false;
    }

    *error_msg = StringPrintf("Unexpected result from analyzing secondary dex %s result=%d",
                              dex_path.c_str(),
                              result);
    return false;
}

enum SecondaryDexAccess {
    kSecondaryDexAccessReadOk = 0,
    kSecondaryDexAccessDoesNotExist = 1,
    kSecondaryDexAccessPermissionError = 2,
    kSecondaryDexAccessIOError = 3
};

static SecondaryDexAccess check_secondary_dex_access(const std::string& dex_path) {
    // Check if the path exists and can be read. If not, there's nothing to do.
    if (access(dex_path.c_str(), R_OK) == 0) {
        return kSecondaryDexAccessReadOk;
    } else {
        if (errno == ENOENT) {
            async_safe_format_log(ANDROID_LOG_INFO, LOG_TAG,
                    "Secondary dex does not exist: %s", dex_path.c_str());
            return kSecondaryDexAccessDoesNotExist;
        } else {
            async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG,
                    "Could not access secondary dex: %s (%d)", dex_path.c_str(), errno);
            return errno == EACCES
                ? kSecondaryDexAccessPermissionError
                : kSecondaryDexAccessIOError;
        }
    }
}

static bool is_file_public(const std::string& filename) {
    struct stat file_stat;
    if (stat(filename.c_str(), &file_stat) == 0) {
        return (file_stat.st_mode & S_IROTH) != 0;
    }
    return false;
}

// Create the oat file structure for the secondary dex 'dex_path' and assign
// the individual path component to the 'out_' parameters.
static bool create_secondary_dex_oat_layout(const std::string& dex_path, const std::string& isa,
        char* out_oat_dir, char* out_oat_isa_dir, char* out_oat_path, std::string* error_msg) {
    size_t dirIndex = dex_path.rfind('/');
    if (dirIndex == std::string::npos) {
        *error_msg = std::string("Unexpected dir structure for dex file ").append(dex_path);
        return false;
    }
    // TODO(calin): we have similar computations in at lest 3 other places
    // (InstalldNativeService, otapropt and dexopt). Unify them and get rid of snprintf by
    // using string append.
    std::string apk_dir = dex_path.substr(0, dirIndex);
    snprintf(out_oat_dir, PKG_PATH_MAX, "%s/oat", apk_dir.c_str());
    snprintf(out_oat_isa_dir, PKG_PATH_MAX, "%s/%s", out_oat_dir, isa.c_str());

    if (!create_oat_out_path(dex_path.c_str(), isa.c_str(), out_oat_dir,
            /*is_secondary_dex*/true, out_oat_path)) {
        *error_msg = std::string("Could not create oat path for secondary dex ").append(dex_path);
        return false;
    }
    return true;
}

// Validate that the dexopt_flags contain a valid storage flag and convert that to an installd
// recognized storage flags (FLAG_STORAGE_CE or FLAG_STORAGE_DE).
static bool validate_dexopt_storage_flags(int dexopt_flags,
                                          int* out_storage_flag,
                                          std::string* error_msg) {
    if ((dexopt_flags & DEXOPT_STORAGE_CE) != 0) {
        *out_storage_flag = FLAG_STORAGE_CE;
        if ((dexopt_flags & DEXOPT_STORAGE_DE) != 0) {
            *error_msg = "Ambiguous secondary dex storage flag. Both, CE and DE, flags are set";
            return false;
        }
    } else if ((dexopt_flags & DEXOPT_STORAGE_DE) != 0) {
        *out_storage_flag = FLAG_STORAGE_DE;
    } else {
        *error_msg = "Secondary dex storage flag must be set";
        return false;
    }
    return true;
}

static bool get_class_loader_context_dex_paths(const char* class_loader_context, int uid,
        /* out */ std::vector<std::string>* context_dex_paths) {
    if (class_loader_context == nullptr) {
      return true;
    }

    LOG(DEBUG) << "Getting dex paths for context " << class_loader_context;

    // Pipe to get the hash result back from our child process.
    unique_fd pipe_read, pipe_write;
    if (!Pipe(&pipe_read, &pipe_write)) {
        PLOG(ERROR) << "Failed to create pipe";
        return false;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // child -- drop privileges before continuing.
        drop_capabilities(uid);

        // Route stdout to `pipe_write`
        while ((dup2(pipe_write, STDOUT_FILENO) == -1) && (errno == EINTR)) {}
        pipe_write.reset();
        pipe_read.reset();

        RunDexoptAnalyzer run_dexopt_analyzer(class_loader_context);
        run_dexopt_analyzer.Exec(kSecondaryDexDexoptAnalyzerSkippedFailExec);
    }

    /* parent */
    pipe_write.reset();

    std::string str_dex_paths;
    if (!ReadFdToString(pipe_read, &str_dex_paths)) {
        PLOG(ERROR) << "Failed to read from pipe";
        return false;
    }
    pipe_read.reset();

    int return_code = wait_child_with_timeout(pid, kShortTimeoutMs);
    if (!WIFEXITED(return_code)) {
        PLOG(ERROR) << "Error waiting for child dexoptanalyzer process";
        return false;
    }

    constexpr int kFlattenClassLoaderContextSuccess = 50;
    return_code = WEXITSTATUS(return_code);
    if (return_code != kFlattenClassLoaderContextSuccess) {
        LOG(ERROR) << "Dexoptanalyzer could not flatten class loader context, code=" << return_code;
        return false;
    }

    if (!str_dex_paths.empty()) {
        *context_dex_paths = android::base::Split(str_dex_paths, ":");
    }
    return true;
}

static int open_dex_paths(const std::vector<std::string>& dex_paths,
        /* out */ std::vector<unique_fd>* zip_fds, /* out */ std::string* error_msg) {
    for (const std::string& dex_path : dex_paths) {
        zip_fds->emplace_back(open(dex_path.c_str(), O_RDONLY));
        if (zip_fds->back().get() < 0) {
            *error_msg = StringPrintf(
                    "installd cannot open '%s' for input during dexopt", dex_path.c_str());
            if (errno == ENOENT) {
                return kSecondaryDexDexoptAnalyzerSkippedNoFile;
            } else {
                return kSecondaryDexDexoptAnalyzerSkippedOpenZip;
            }
        }
    }
    return 0;
}

static std::string join_fds(const std::vector<unique_fd>& fds) {
    std::stringstream ss;
    bool is_first = true;
    for (const unique_fd& fd : fds) {
        if (is_first) {
            is_first = false;
        } else {
            ss << ":";
        }
        ss << fd.get();
    }
    return ss.str();
}

void control_dexopt_blocking(bool block) {
    dexopt_status_->control_dexopt_blocking(block);
}

bool is_dexopt_blocked() {
    return dexopt_status_->is_dexopt_blocked();
}

enum SecondaryDexOptProcessResult {
    kSecondaryDexOptProcessOk = 0,
    kSecondaryDexOptProcessCancelled = 1,
    kSecondaryDexOptProcessError = 2
};

// Processes the dex_path as a secondary dex files and return true if the path dex file should
// be compiled.
// Returns: kSecondaryDexOptProcessError for errors (logged).
//          kSecondaryDexOptProcessOk if the secondary dex path was process successfully.
//          kSecondaryDexOptProcessCancelled if the processing was cancelled.
//
// When returning kSecondaryDexOptProcessOk, the output parameters will be:
//   - is_public_out: whether or not the oat file should not be made public
//   - dexopt_needed_out: valid OatFileAsssitant::DexOptNeeded
//   - oat_dir_out: the oat dir path where the oat file should be stored
static SecondaryDexOptProcessResult process_secondary_dex_dexopt(const std::string& dex_path,
        const char* pkgname, int dexopt_flags, const char* volume_uuid, int uid,
        const char* instruction_set, const char* compiler_filter, bool* is_public_out,
        int* dexopt_needed_out, std::string* oat_dir_out, bool downgrade,
        const char* class_loader_context, const std::vector<std::string>& context_dex_paths,
        /* out */ std::string* error_msg) {
    LOG(DEBUG) << "Processing secondary dex path " << dex_path;

    if (dexopt_status_->is_dexopt_blocked()) {
        return kSecondaryDexOptProcessCancelled;
    }

    int storage_flag;
    if (!validate_dexopt_storage_flags(dexopt_flags, &storage_flag, error_msg)) {
        LOG(ERROR) << *error_msg;
        return kSecondaryDexOptProcessError;
    }
    // Compute the oat dir as it's not easy to extract it from the child computation.
    char oat_path[PKG_PATH_MAX];
    char oat_dir[PKG_PATH_MAX];
    char oat_isa_dir[PKG_PATH_MAX];
    if (!create_secondary_dex_oat_layout(
            dex_path, instruction_set, oat_dir, oat_isa_dir, oat_path, error_msg)) {
        LOG(ERROR) << "Could not create secondary odex layout: " << *error_msg;
        return kSecondaryDexOptProcessError;
    }
    oat_dir_out->assign(oat_dir);

    bool cancelled = false;
    pid_t pid = dexopt_status_->check_cancellation_and_fork(&cancelled);
    if (cancelled) {
        return kSecondaryDexOptProcessCancelled;
    }
    if (pid == 0) {
        // child -- drop privileges before continuing.
        drop_capabilities(uid);

        // Validate the path structure.
        if (!validate_secondary_dex_path(pkgname, dex_path, volume_uuid, uid, storage_flag)) {
            async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG,
                    "Could not validate secondary dex path %s", dex_path.c_str());
            _exit(kSecondaryDexDexoptAnalyzerSkippedValidatePath);
        }

        // Open the dex file.
        unique_fd zip_fd;
        zip_fd.reset(open(dex_path.c_str(), O_RDONLY));
        if (zip_fd.get() < 0) {
            if (errno == ENOENT) {
                _exit(kSecondaryDexDexoptAnalyzerSkippedNoFile);
            } else {
                _exit(kSecondaryDexDexoptAnalyzerSkippedOpenZip);
            }
        }

        // Open class loader context dex files.
        std::vector<unique_fd> context_zip_fds;
        int open_dex_paths_rc = open_dex_paths(context_dex_paths, &context_zip_fds, error_msg);
        if (open_dex_paths_rc != 0) {
            _exit(open_dex_paths_rc);
        }

        // Prepare the oat directories.
        if (!prepare_secondary_dex_oat_dir(dex_path, uid, instruction_set)) {
            _exit(kSecondaryDexDexoptAnalyzerSkippedPrepareDir);
        }

        // Open the vdex/oat files if any.
        unique_fd oat_file_fd;
        unique_fd vdex_file_fd;
        if (!maybe_open_oat_and_vdex_file(dex_path,
                                          *oat_dir_out,
                                          instruction_set,
                                          true /* is_secondary_dex */,
                                          &oat_file_fd,
                                          &vdex_file_fd)) {
            _exit(kSecondaryDexDexoptAnalyzerSkippedOpenOutput);
        }

        // Analyze profiles.
        int profile_analysis_result = analyze_profiles(uid, pkgname, dex_path,
                /*is_secondary_dex*/true);

        // Run dexoptanalyzer to get dexopt_needed code. This is not expected to return.
        // Note that we do not do it before the fork since opening the files is required to happen
        // after forking.
        RunDexoptAnalyzer run_dexopt_analyzer(dex_path,
                                              vdex_file_fd.get(),
                                              oat_file_fd.get(),
                                              zip_fd.get(),
                                              instruction_set,
                                              compiler_filter,
                                              profile_analysis_result,
                                              downgrade,
                                              class_loader_context,
                                              join_fds(context_zip_fds));
        run_dexopt_analyzer.Exec(kSecondaryDexDexoptAnalyzerSkippedFailExec);
    }

    /* parent */
    int result = wait_child_with_timeout(pid, kShortTimeoutMs);
    cancelled = dexopt_status_->check_if_killed_and_remove_dexopt_pid(pid);
    if (!WIFEXITED(result)) {
        if ((WTERMSIG(result) == SIGKILL) && cancelled) {
            LOG(INFO) << "dexoptanalyzer cancelled for path:" << dex_path;
            return kSecondaryDexOptProcessCancelled;
        }
        *error_msg = StringPrintf("dexoptanalyzer failed for path %s: 0x%04x",
                                  dex_path.c_str(),
                                  result);
        LOG(ERROR) << *error_msg;
        return kSecondaryDexOptProcessError;
    }
    result = WEXITSTATUS(result);
    // Check that we successfully executed dexoptanalyzer.
    bool success = process_secondary_dexoptanalyzer_result(dex_path,
                                                           result,
                                                           dexopt_needed_out,
                                                           error_msg);
    if (!success) {
        LOG(ERROR) << *error_msg;
    }

    LOG(DEBUG) << "Processed secondary dex file " << dex_path << " result=" << result;

    // Run dexopt only if needed or forced.
    // Note that dexoptanalyzer is executed even if force compilation is enabled (because it
    // makes the code simpler; force compilation is only needed during tests).
    if (success &&
        (result != kSecondaryDexDexoptAnalyzerSkippedNoFile) &&
        ((dexopt_flags & DEXOPT_FORCE) != 0)) {
        *dexopt_needed_out = DEX2OAT_FROM_SCRATCH;
    }

    // Check if we should make the oat file public.
    // Note that if the dex file is not public the compiled code cannot be made public.
    // It is ok to check this flag outside in the parent process.
    *is_public_out = ((dexopt_flags & DEXOPT_PUBLIC) != 0) && is_file_public(dex_path);

    return success ? kSecondaryDexOptProcessOk : kSecondaryDexOptProcessError;
}

static std::string format_dexopt_error(int status, const char* dex_path) {
  if (WIFEXITED(status)) {
    int int_code = WEXITSTATUS(status);
    const char* code_name = get_return_code_name(static_cast<DexoptReturnCodes>(int_code));
    if (code_name != nullptr) {
      return StringPrintf("Dex2oat invocation for %s failed: %s", dex_path, code_name);
    }
  }
  return StringPrintf("Dex2oat invocation for %s failed with 0x%04x", dex_path, status);
}


int dexopt(const char* dex_path, uid_t uid, const char* pkgname, const char* instruction_set,
        int dexopt_needed, const char* oat_dir, int dexopt_flags, const char* compiler_filter,
        const char* volume_uuid, const char* class_loader_context, const char* se_info,
        bool downgrade, int target_sdk_version, const char* profile_name,
        const char* dex_metadata_path, const char* compilation_reason, std::string* error_msg,
        /* out */ bool* completed) {
    CHECK(pkgname != nullptr);
    CHECK(pkgname[0] != 0);
    CHECK(error_msg != nullptr);
    CHECK_EQ(dexopt_flags & ~DEXOPT_MASK, 0)
        << "dexopt flags contains unknown fields: " << dexopt_flags;

    bool local_completed; // local placeholder for nullptr case
    if (completed == nullptr) {
        completed = &local_completed;
    }
    *completed = true;
    if (dexopt_status_->is_dexopt_blocked()) {
        *completed = false;
        return 0;
    }

    if (!validate_dex_path_size(dex_path)) {
        *error_msg = StringPrintf("Failed to validate %s", dex_path);
        return -1;
    }

    if (class_loader_context != nullptr && strlen(class_loader_context) > PKG_PATH_MAX) {
        *error_msg = StringPrintf("Class loader context exceeds the allowed size: %s",
                                  class_loader_context);
        LOG(ERROR) << *error_msg;
        return -1;
    }

    bool is_public = (dexopt_flags & DEXOPT_PUBLIC) != 0;
    bool debuggable = (dexopt_flags & DEXOPT_DEBUGGABLE) != 0;
    bool boot_complete = (dexopt_flags & DEXOPT_BOOTCOMPLETE) != 0;
    bool profile_guided = (dexopt_flags & DEXOPT_PROFILE_GUIDED) != 0;
    bool is_secondary_dex = (dexopt_flags & DEXOPT_SECONDARY_DEX) != 0;
    bool background_job_compile = (dexopt_flags & DEXOPT_IDLE_BACKGROUND_JOB) != 0;
    bool enable_hidden_api_checks = (dexopt_flags & DEXOPT_ENABLE_HIDDEN_API_CHECKS) != 0;
    bool generate_compact_dex = (dexopt_flags & DEXOPT_GENERATE_COMPACT_DEX) != 0;
    bool generate_app_image = (dexopt_flags & DEXOPT_GENERATE_APP_IMAGE) != 0;
    bool for_restore = (dexopt_flags & DEXOPT_FOR_RESTORE) != 0;

    // Check if we're dealing with a secondary dex file and if we need to compile it.
    std::string oat_dir_str;
    std::vector<std::string> context_dex_paths;
    if (is_secondary_dex) {
        if (!get_class_loader_context_dex_paths(class_loader_context, uid, &context_dex_paths)) {
            *error_msg = "Failed acquiring context dex paths";
            return -1;  // We had an error, logged in the process method.
        }
        SecondaryDexOptProcessResult sec_dex_result = process_secondary_dex_dexopt(dex_path,
                pkgname, dexopt_flags, volume_uuid, uid,instruction_set, compiler_filter,
                &is_public, &dexopt_needed, &oat_dir_str, downgrade, class_loader_context,
                context_dex_paths, error_msg);
        if (sec_dex_result == kSecondaryDexOptProcessOk) {
            oat_dir = oat_dir_str.c_str();
            if (dexopt_needed == NO_DEXOPT_NEEDED) {
                *completed = true;
                return 0;  // Nothing to do, report success.
            }
        } else if (sec_dex_result == kSecondaryDexOptProcessCancelled) {
            // cancelled, not an error.
            *completed = false;
            return 0;
        } else {
            if (error_msg->empty()) {  // TODO: Make this a CHECK.
                *error_msg = "Failed processing secondary.";
            }
            return -1;  // We had an error, logged in the process method.
        }
    } else {
        // Currently these flags are only used for secondary dex files.
        // Verify that they are not set for primary apks.
        CHECK((dexopt_flags & DEXOPT_STORAGE_CE) == 0);
        CHECK((dexopt_flags & DEXOPT_STORAGE_DE) == 0);
    }

    // Open the input file.
    UniqueFile in_dex(open(dex_path, O_RDONLY, 0), dex_path);
    if (in_dex.fd() < 0) {
        *error_msg = StringPrintf("installd cannot open '%s' for input during dexopt", dex_path);
        LOG(ERROR) << *error_msg;
        return -1;
    }

    // Open class loader context dex files.
    std::vector<unique_fd> context_input_fds;
    if (open_dex_paths(context_dex_paths, &context_input_fds, error_msg) != 0) {
        LOG(ERROR) << *error_msg;
        return -1;
    }

    // Create the output OAT file.
    RestorableFile out_oat =
            open_oat_out_file(dex_path, oat_dir, is_public, uid, instruction_set, is_secondary_dex);
    if (out_oat.fd() < 0) {
        *error_msg = "Could not open out oat file.";
        return -1;
    }

    // Open vdex files.
    UniqueFile in_vdex;
    RestorableFile out_vdex;
    if (!open_vdex_files_for_dex2oat(dex_path, out_oat.path().c_str(), dexopt_needed,
            instruction_set, is_public, uid, is_secondary_dex, profile_guided, &in_vdex,
            &out_vdex)) {
        *error_msg = "Could not open vdex files.";
        return -1;
    }

    // Ensure that the oat dir and the compiler artifacts of secondary dex files have the correct
    // selinux context (we generate them on the fly during the dexopt invocation and they don't
    // fully inherit their parent context).
    // Note that for primary apk the oat files are created before, in a separate installd
    // call which also does the restorecon. TODO(calin): unify the paths.
    if (is_secondary_dex) {
        if (selinux_android_restorecon_pkgdir(oat_dir, se_info, uid,
                SELINUX_ANDROID_RESTORECON_RECURSE)) {
            *error_msg = std::string("Failed to restorecon ").append(oat_dir);
            LOG(ERROR) << *error_msg;
            return -1;
        }
    }

    // Create a swap file if necessary.
    unique_fd swap_fd = maybe_open_dexopt_swap_file(out_oat.path());

    // Open the reference profile if needed.
    UniqueFile reference_profile = maybe_open_reference_profile(
            pkgname, dex_path, profile_name, profile_guided, is_public, uid, is_secondary_dex);
    struct stat sbuf;
    if (reference_profile.fd() == -1 ||
        (fstat(reference_profile.fd(), &sbuf) != -1 && sbuf.st_size == 0)) {
        // We don't create an app image with empty or non existing reference profile since there
        // is no speedup from loading it in that case and instead will be a small overhead.
        generate_app_image = false;
    }

    // Create the app image file if needed.
    RestorableFile out_image = maybe_open_app_image(out_oat.path(), generate_app_image, is_public,
                                                    uid, is_secondary_dex);

    UniqueFile dex_metadata;
    if (dex_metadata_path != nullptr) {
        dex_metadata.reset(TEMP_FAILURE_RETRY(open(dex_metadata_path, O_RDONLY | O_NOFOLLOW)),
                           dex_metadata_path);
        if (dex_metadata.fd() < 0) {
            PLOG(ERROR) << "Failed to open dex metadata file " << dex_metadata_path;
        }
    }

    std::string jitzygote_flag = server_configurable_flags::GetServerConfigurableFlag(
        RUNTIME_NATIVE_BOOT_NAMESPACE,
        ENABLE_JITZYGOTE_IMAGE,
        /*default_value=*/ "");
    bool compile_without_image = jitzygote_flag == "true" || IsBootClassPathProfilingEnable() ||
            force_compile_without_image();

    // Decide whether to use dex2oat64.
    bool use_dex2oat64 = false;
    // Check whether the device even supports 64-bit ABIs.
    if (!GetProperty("ro.product.cpu.abilist64", "").empty()) {
      use_dex2oat64 = GetBoolProperty("dalvik.vm.dex2oat64.enabled", false);
    }
    const char* dex2oat_bin = select_execution_binary(
        (use_dex2oat64 ? kDex2oat64Path : kDex2oat32Path),
        (use_dex2oat64 ? kDex2oatDebug64Path : kDex2oatDebug32Path),
        background_job_compile);

    auto execv_helper = std::make_unique<ExecVHelper>();

    LOG(VERBOSE) << "DexInv: --- BEGIN '" << dex_path << "' ---";

    RunDex2Oat runner(dex2oat_bin, execv_helper.get());
    runner.Initialize(out_oat.GetUniqueFile(), out_vdex.GetUniqueFile(), out_image.GetUniqueFile(),
                      in_dex, in_vdex, dex_metadata, reference_profile, class_loader_context,
                      join_fds(context_input_fds), swap_fd.get(), instruction_set, compiler_filter,
                      debuggable, boot_complete, for_restore, target_sdk_version,
                      enable_hidden_api_checks, generate_compact_dex, compile_without_image,
                      background_job_compile, compilation_reason);

    bool cancelled = false;
    pid_t pid = dexopt_status_->check_cancellation_and_fork(&cancelled);
    if (cancelled) {
        *completed = false;
        reference_profile.DisableCleanup();
        return 0;
    }
    if (pid == 0) {
        // Need to set schedpolicy before dropping privileges
        // for cgroup migration. See details at b/175178520.
        SetDex2OatScheduling(boot_complete);

        /* child -- drop privileges before continuing */
        drop_capabilities(uid);

        if (flock(out_oat.fd(), LOCK_EX | LOCK_NB) != 0) {
            async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "flock(%s) failed",
                    out_oat.path().c_str());
            _exit(DexoptReturnCodes::kFlock);
        }

        runner.Exec(DexoptReturnCodes::kDex2oatExec);
    } else {
        int res = wait_child_with_timeout(pid, kLongTimeoutMs);
        bool cancelled = dexopt_status_->check_if_killed_and_remove_dexopt_pid(pid);
        if (res == 0) {
            LOG(VERBOSE) << "DexInv: --- END '" << dex_path << "' (success) ---";
        } else {
            if ((WTERMSIG(res) == SIGKILL) && cancelled) {
                LOG(VERBOSE) << "DexInv: --- END '" << dex_path << "' --- cancelled";
                // cancelled, not an error
                *completed = false;
                reference_profile.DisableCleanup();
                return 0;
            }
            LOG(VERBOSE) << "DexInv: --- END '" << dex_path << "' --- status=0x"
                         << std::hex << std::setw(4) << res << ", process failed";
            *error_msg = format_dexopt_error(res, dex_path);
            return res;
        }
    }

    // dex2oat ran successfully, so profile is safe to keep.
    reference_profile.DisableCleanup();

    // We've been successful, commit work files.
    // If committing (=renaming tmp to regular) fails, try to restore backup files.
    // If restoring fails as well, as a last resort, remove all files.
    if (!out_oat.CreateBackupFile() || !out_vdex.CreateBackupFile() ||
        !out_image.CreateBackupFile()) {
        // Renaming failure can mean that the original file may not be accessible from installd.
        LOG(ERROR) << "Cannot create backup file from existing file, file in wrong state?"
                   << ", out_oat:" << out_oat.path() << " ,out_vdex:" << out_vdex.path()
                   << " ,out_image:" << out_image.path();
        out_oat.ResetAndRemoveAllFiles();
        out_vdex.ResetAndRemoveAllFiles();
        out_image.ResetAndRemoveAllFiles();
        return -1;
    }
    if (!out_oat.CommitWorkFile() || !out_vdex.CommitWorkFile() || !out_image.CommitWorkFile()) {
        LOG(ERROR) << "Cannot commit, out_oat:" << out_oat.path()
                   << " ,out_vdex:" << out_vdex.path() << " ,out_image:" << out_image.path();
        if (!out_oat.RestoreBackupFile() || !out_vdex.RestoreBackupFile() ||
            !out_image.RestoreBackupFile()) {
            LOG(ERROR) << "Cannot cancel commit, out_oat:" << out_oat.path()
                       << " ,out_vdex:" << out_vdex.path() << " ,out_image:" << out_image.path();
            // Restoring failed.
            out_oat.ResetAndRemoveAllFiles();
            out_vdex.ResetAndRemoveAllFiles();
            out_image.ResetAndRemoveAllFiles();
        }
        return -1;
    }
    // Now remove remaining backup files.
    out_oat.RemoveBackupFile();
    out_vdex.RemoveBackupFile();
    out_image.RemoveBackupFile();

    *completed = true;
    return 0;
}

// Try to remove the given directory. Log an error if the directory exists
// and is empty but could not be removed.
static bool rmdir_if_empty(const char* dir) {
    if (rmdir(dir) == 0) {
        return true;
    }
    if (errno == ENOENT || errno == ENOTEMPTY) {
        return true;
    }
    PLOG(ERROR) << "Failed to remove dir: " << dir;
    return false;
}

// Try to unlink the given file. Log an error if the file exists and could not
// be unlinked.
static bool unlink_if_exists(const std::string& file) {
    if (unlink(file.c_str()) == 0) {
        return true;
    }
    if (errno == ENOENT) {
        return true;

    }
    PLOG(ERROR) << "Could not unlink: " << file;
    return false;
}

enum ReconcileSecondaryDexResult {
    kReconcileSecondaryDexExists = 0,
    kReconcileSecondaryDexCleanedUp = 1,
    kReconcileSecondaryDexValidationError = 2,
    kReconcileSecondaryDexCleanUpError = 3,
    kReconcileSecondaryDexAccessIOError = 4,
};

// Reconcile the secondary dex 'dex_path' and its generated oat files.
// Return true if all the parameters are valid and the secondary dex file was
//   processed successfully (i.e. the dex_path either exists, or if not, its corresponding
//   oat/vdex/art files where deleted successfully). In this case, out_secondary_dex_exists
//   will be true if the secondary dex file still exists. If the secondary dex file does not exist,
//   the method cleans up any previously generated compiler artifacts (oat, vdex, art).
// Return false if there were errors during processing. In this case
//   out_secondary_dex_exists will be set to false.
bool reconcile_secondary_dex_file(const std::string& dex_path,
        const std::string& pkgname, int uid, const std::vector<std::string>& isas,
        const std::optional<std::string>& volume_uuid, int storage_flag,
        /*out*/bool* out_secondary_dex_exists) {
    *out_secondary_dex_exists = false;  // start by assuming the file does not exist.
    if (isas.size() == 0) {
        LOG(ERROR) << "reconcile_secondary_dex_file called with empty isas vector";
        return false;
    }

    if (storage_flag != FLAG_STORAGE_CE && storage_flag != FLAG_STORAGE_DE) {
        LOG(ERROR) << "reconcile_secondary_dex_file called with invalid storage_flag: "
                << storage_flag;
        return false;
    }

    // As a security measure we want to unlink art artifacts with the reduced capabilities
    // of the package user id. So we fork and drop capabilities in the child.
    pid_t pid = fork();
    if (pid == 0) {
        /* child -- drop privileges before continuing */
        drop_capabilities(uid);

        const char* volume_uuid_cstr = volume_uuid ? volume_uuid->c_str() : nullptr;
        if (!validate_secondary_dex_path(pkgname, dex_path, volume_uuid_cstr,
                uid, storage_flag)) {
            async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG,
                    "Could not validate secondary dex path %s", dex_path.c_str());
            _exit(kReconcileSecondaryDexValidationError);
        }

        SecondaryDexAccess access_check = check_secondary_dex_access(dex_path);
        switch (access_check) {
            case kSecondaryDexAccessDoesNotExist:
                 // File does not exist. Proceed with cleaning.
                break;
            case kSecondaryDexAccessReadOk: _exit(kReconcileSecondaryDexExists);
            case kSecondaryDexAccessIOError: _exit(kReconcileSecondaryDexAccessIOError);
            case kSecondaryDexAccessPermissionError: _exit(kReconcileSecondaryDexValidationError);
            default:
                async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG,
                        "Unexpected result from check_secondary_dex_access: %d", access_check);
                _exit(kReconcileSecondaryDexValidationError);
        }

        // The secondary dex does not exist anymore or it's. Clear any generated files.
        char oat_path[PKG_PATH_MAX];
        char oat_dir[PKG_PATH_MAX];
        char oat_isa_dir[PKG_PATH_MAX];
        bool result = true;
        for (size_t i = 0; i < isas.size(); i++) {
            std::string error_msg;
            if (!create_secondary_dex_oat_layout(
                    dex_path,isas[i], oat_dir, oat_isa_dir, oat_path, &error_msg)) {
                async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "%s", error_msg.c_str());
                _exit(kReconcileSecondaryDexValidationError);
            }

            // Delete oat/vdex/art files.
            result = unlink_if_exists(oat_path) && result;
            result = unlink_if_exists(create_vdex_filename(oat_path)) && result;
            result = unlink_if_exists(create_image_filename(oat_path)) && result;

            // Delete profiles.
            std::string current_profile = create_current_profile_path(
                multiuser_get_user_id(uid), pkgname, dex_path, /*is_secondary*/true);
            std::string reference_profile = create_reference_profile_path(
                pkgname, dex_path, /*is_secondary*/true);
            result = unlink_if_exists(current_profile) && result;
            result = unlink_if_exists(reference_profile) && result;

            // We upgraded once the location of current profile for secondary dex files.
            // Check for any previous left-overs and remove them as well.
            std::string old_current_profile = dex_path + ".prof";
            result = unlink_if_exists(old_current_profile);

            // Try removing the directories as well, they might be empty.
            result = rmdir_if_empty(oat_isa_dir) && result;
            result = rmdir_if_empty(oat_dir) && result;
        }
        if (!result) {
            async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG,
                    "Could not validate secondary dex path %s", dex_path.c_str());
        }
        _exit(result ? kReconcileSecondaryDexCleanedUp : kReconcileSecondaryDexAccessIOError);
    }

    int return_code = wait_child_with_timeout(pid, kShortTimeoutMs);
    if (!WIFEXITED(return_code)) {
        LOG(WARNING) << "reconcile dex failed for location " << dex_path << ": " << return_code;
    } else {
        return_code = WEXITSTATUS(return_code);
    }

    LOG(DEBUG) << "Reconcile secondary dex path " << dex_path << " result=" << return_code;

    switch (return_code) {
        case kReconcileSecondaryDexCleanedUp:
        case kReconcileSecondaryDexValidationError:
            // If we couldn't validate assume the dex file does not exist.
            // This will purge the entry from the PM records.
            *out_secondary_dex_exists = false;
            return true;
        case kReconcileSecondaryDexExists:
            *out_secondary_dex_exists = true;
            return true;
        case kReconcileSecondaryDexAccessIOError:
            // We had an access IO error.
            // Return false so that we can try again.
            // The value of out_secondary_dex_exists does not matter in this case and by convention
            // is set to false.
            *out_secondary_dex_exists = false;
            return false;
        default:
            LOG(ERROR) << "Unexpected code from reconcile_secondary_dex_file: " << return_code;
            *out_secondary_dex_exists = false;
            return false;
    }
}

// Compute and return the hash (SHA-256) of the secondary dex file at dex_path.
// Returns true if all parameters are valid and the hash successfully computed and stored in
// out_secondary_dex_hash.
// Also returns true with an empty hash if the file does not currently exist or is not accessible to
// the app.
// For any other errors (e.g. if any of the parameters are invalid) returns false.
bool hash_secondary_dex_file(const std::string& dex_path, const std::string& pkgname, int uid,
        const std::optional<std::string>& volume_uuid, int storage_flag,
        std::vector<uint8_t>* out_secondary_dex_hash) {
    out_secondary_dex_hash->clear();

    const char* volume_uuid_cstr = volume_uuid ? volume_uuid->c_str() : nullptr;

    if (storage_flag != FLAG_STORAGE_CE && storage_flag != FLAG_STORAGE_DE) {
        LOG(ERROR) << "hash_secondary_dex_file called with invalid storage_flag: "
                << storage_flag;
        return false;
    }

    // Pipe to get the hash result back from our child process.
    unique_fd pipe_read, pipe_write;
    if (!Pipe(&pipe_read, &pipe_write)) {
        PLOG(ERROR) << "Failed to create pipe";
        return false;
    }

    // Fork so that actual access to the files is done in the app's own UID, to ensure we only
    // access data the app itself can access.
    pid_t pid = fork();
    if (pid == 0) {
        // child -- drop privileges before continuing
        drop_capabilities(uid);
        pipe_read.reset();

        if (!validate_secondary_dex_path(pkgname, dex_path, volume_uuid_cstr, uid, storage_flag)) {
            async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG,
                    "Could not validate secondary dex path %s", dex_path.c_str());
            _exit(DexoptReturnCodes::kHashValidatePath);
        }

        unique_fd fd(TEMP_FAILURE_RETRY(open(dex_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)));
        if (fd == -1) {
            if (errno == EACCES || errno == ENOENT) {
                // Not treated as an error.
                _exit(0);
            }
            PLOG(ERROR) << "Failed to open secondary dex " << dex_path;
            async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG,
                    "Failed to open secondary dex %s: %d", dex_path.c_str(), errno);
            _exit(DexoptReturnCodes::kHashOpenPath);
        }

        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        std::vector<uint8_t> buffer(65536);
        while (true) {
            ssize_t bytes_read = TEMP_FAILURE_RETRY(read(fd, buffer.data(), buffer.size()));
            if (bytes_read == 0) {
                break;
            } else if (bytes_read == -1) {
                async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG,
                        "Failed to read secondary dex %s: %d", dex_path.c_str(), errno);
                _exit(DexoptReturnCodes::kHashReadDex);
            }

            SHA256_Update(&ctx, buffer.data(), bytes_read);
        }

        std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
        SHA256_Final(hash.data(), &ctx);
        if (!WriteFully(pipe_write, hash.data(), hash.size())) {
            _exit(DexoptReturnCodes::kHashWrite);
        }

        _exit(0);
    }

    // parent
    pipe_write.reset();

    out_secondary_dex_hash->resize(SHA256_DIGEST_LENGTH);
    if (!ReadFully(pipe_read, out_secondary_dex_hash->data(), out_secondary_dex_hash->size())) {
        out_secondary_dex_hash->clear();
    }
    return wait_child_with_timeout(pid, kShortTimeoutMs) == 0;
}

// Helper for move_ab, so that we can have common failure-case cleanup.
static bool unlink_and_rename(const char* from, const char* to) {
    // Check whether "from" exists, and if so whether it's regular. If it is, unlink. Otherwise,
    // return a failure.
    struct stat s;
    if (stat(to, &s) == 0) {
        if (!S_ISREG(s.st_mode)) {
            LOG(ERROR) << from << " is not a regular file to replace for A/B.";
            return false;
        }
        if (unlink(to) != 0) {
            LOG(ERROR) << "Could not unlink " << to << " to move A/B.";
            return false;
        }
    } else {
        // This may be a permission problem. We could investigate the error code, but we'll just
        // let the rename failure do the work for us.
    }

    // Try to rename "to" to "from."
    if (rename(from, to) != 0) {
        PLOG(ERROR) << "Could not rename " << from << " to " << to;
        return false;
    }
    return true;
}

// Move/rename a B artifact (from) to an A artifact (to).
static bool move_ab_path(const std::string& b_path, const std::string& a_path) {
    // Check whether B exists.
    {
        struct stat s;
        if (stat(b_path.c_str(), &s) != 0) {
            // Ignore for now. The service calling this isn't smart enough to
            // understand lack of artifacts at the moment.
            LOG(VERBOSE) << "A/B artifact " << b_path << " does not exist!";
            return false;
        }
        if (!S_ISREG(s.st_mode)) {
            LOG(ERROR) << "A/B artifact " << b_path << " is not a regular file.";
            // Try to unlink, but swallow errors.
            unlink(b_path.c_str());
            return false;
        }
    }

    // Rename B to A.
    if (!unlink_and_rename(b_path.c_str(), a_path.c_str())) {
        // Delete the b_path so we don't try again (or fail earlier).
        if (unlink(b_path.c_str()) != 0) {
            PLOG(ERROR) << "Could not unlink " << b_path;
        }

        return false;
    }

    return true;
}

bool move_ab(const char* apk_path, const char* instruction_set, const char* oat_dir) {
    // Get the current slot suffix. No suffix, no A/B.
    const std::string slot_suffix = GetProperty("ro.boot.slot_suffix", "");
    if (slot_suffix.empty()) {
        return false;
    }

    if (!ValidateTargetSlotSuffix(slot_suffix)) {
        LOG(ERROR) << "Target slot suffix not legal: " << slot_suffix;
        return false;
    }

    // Validate other inputs.
    if (validate_apk_path(apk_path) != 0) {
        LOG(ERROR) << "Invalid apk_path: " << apk_path;
        return false;
    }
    if (validate_apk_path(oat_dir) != 0) {
        LOG(ERROR) << "Invalid oat_dir: " << oat_dir;
        return false;
    }

    char a_path[PKG_PATH_MAX];
    if (!calculate_oat_file_path(a_path, oat_dir, apk_path, instruction_set)) {
        return false;
    }
    const std::string a_vdex_path = create_vdex_filename(a_path);
    const std::string a_image_path = create_image_filename(a_path);

    // B path = A path + slot suffix.
    const std::string b_path = StringPrintf("%s.%s", a_path, slot_suffix.c_str());
    const std::string b_vdex_path = StringPrintf("%s.%s", a_vdex_path.c_str(), slot_suffix.c_str());
    const std::string b_image_path = StringPrintf("%s.%s",
                                                  a_image_path.c_str(),
                                                  slot_suffix.c_str());

    bool success = true;
    if (move_ab_path(b_path, a_path)) {
        if (move_ab_path(b_vdex_path, a_vdex_path)) {
            // Note: we can live without an app image. As such, ignore failure to move the image file.
            //       If we decide to require the app image, or the app image being moved correctly,
            //       then change accordingly.
            constexpr bool kIgnoreAppImageFailure = true;

            if (!a_image_path.empty()) {
                if (!move_ab_path(b_image_path, a_image_path)) {
                    unlink(a_image_path.c_str());
                    if (!kIgnoreAppImageFailure) {
                        success = false;
                    }
                }
            }
        } else {
            // Cleanup: delete B image, ignore errors.
            unlink(b_image_path.c_str());
            success = false;
        }
    } else {
        // Cleanup: delete B image, ignore errors.
        unlink(b_vdex_path.c_str());
        unlink(b_image_path.c_str());
        success = false;
    }
    return success;
}

int64_t delete_odex(const char* apk_path, const char* instruction_set, const char* oat_dir) {
    // Delete the oat/odex file.
    char out_path[PKG_PATH_MAX];
    if (!create_oat_out_path(apk_path, instruction_set, oat_dir,
            /*is_secondary_dex*/false, out_path)) {
        LOG(ERROR) << "Cannot create apk path for " << apk_path;
        return -1;
    }

    // In case of a permission failure report the issue. Otherwise just print a warning.
    auto unlink_and_check = [](const char* path) -> int64_t {
        struct stat file_stat;
        if (stat(path, &file_stat) != 0) {
            if (errno != ENOENT) {
                PLOG(ERROR) << "Could not stat " << path;
                return -1;
            }
            return 0;
        }

        if (unlink(path) != 0) {
            if (errno != ENOENT) {
                PLOG(ERROR) << "Could not unlink " << path;
                return -1;
            }
        }
        return static_cast<int64_t>(file_stat.st_size);
    };

    // Delete the oat/odex file.
    int64_t return_value_oat = unlink_and_check(out_path);

    // Derive and delete the app image.
    int64_t return_value_art = unlink_and_check(create_image_filename(out_path).c_str());

    // Derive and delete the vdex file.
    int64_t return_value_vdex = unlink_and_check(create_vdex_filename(out_path).c_str());

    // Report result
    if (return_value_oat == -1
            || return_value_art == -1
            || return_value_vdex == -1) {
        return -1;
    }

    return return_value_oat + return_value_art + return_value_vdex;
}

static bool is_absolute_path(const std::string& path) {
    if (path.find('/') != 0 || path.find("..") != std::string::npos) {
        LOG(ERROR) << "Invalid absolute path " << path;
        return false;
    } else {
        return true;
    }
}

static bool is_valid_instruction_set(const std::string& instruction_set) {
    // TODO: add explicit whitelisting of instruction sets
    if (instruction_set.find('/') != std::string::npos) {
        LOG(ERROR) << "Invalid instruction set " << instruction_set;
        return false;
    } else {
        return true;
    }
}

bool calculate_oat_file_path_default(char path[PKG_PATH_MAX], const char *oat_dir,
        const char *apk_path, const char *instruction_set) {
    std::string oat_dir_ = oat_dir;
    std::string apk_path_ = apk_path;
    std::string instruction_set_ = instruction_set;

    if (!is_absolute_path(oat_dir_)) return false;
    if (!is_absolute_path(apk_path_)) return false;
    if (!is_valid_instruction_set(instruction_set_)) return false;

    std::string::size_type end = apk_path_.rfind('.');
    std::string::size_type start = apk_path_.rfind('/', end);
    if (end == std::string::npos || start == std::string::npos) {
        LOG(ERROR) << "Invalid apk_path " << apk_path_;
        return false;
    }

    std::string res_ = oat_dir_ + '/' + instruction_set + '/'
            + apk_path_.substr(start + 1, end - start - 1) + ".odex";
    const char* res = res_.c_str();
    if (strlen(res) >= PKG_PATH_MAX) {
        LOG(ERROR) << "Result too large";
        return false;
    } else {
        strlcpy(path, res, PKG_PATH_MAX);
        return true;
    }
}

bool calculate_odex_file_path_default(char path[PKG_PATH_MAX], const char *apk_path,
        const char *instruction_set) {
    std::string apk_path_ = apk_path;
    std::string instruction_set_ = instruction_set;

    if (!is_absolute_path(apk_path_)) return false;
    if (!is_valid_instruction_set(instruction_set_)) return false;

    std::string::size_type end = apk_path_.rfind('.');
    std::string::size_type start = apk_path_.rfind('/', end);
    if (end == std::string::npos || start == std::string::npos) {
        LOG(ERROR) << "Invalid apk_path " << apk_path_;
        return false;
    }

    std::string oat_dir = apk_path_.substr(0, start + 1) + "oat";
    return calculate_oat_file_path_default(path, oat_dir.c_str(), apk_path, instruction_set);
}

bool create_cache_path_default(char path[PKG_PATH_MAX], const char *src,
        const char *instruction_set) {
    std::string src_ = src;
    std::string instruction_set_ = instruction_set;

    if (!is_absolute_path(src_)) return false;
    if (!is_valid_instruction_set(instruction_set_)) return false;

    for (auto it = src_.begin() + 1; it < src_.end(); ++it) {
        if (*it == '/') {
            *it = '@';
        }
    }

    std::string res_ = android_data_dir + DALVIK_CACHE + '/' + instruction_set_ + src_
            + DALVIK_CACHE_POSTFIX;
    const char* res = res_.c_str();
    if (strlen(res) >= PKG_PATH_MAX) {
        LOG(ERROR) << "Result too large";
        return false;
    } else {
        strlcpy(path, res, PKG_PATH_MAX);
        return true;
    }
}

bool open_classpath_files(const std::string& classpath, std::vector<unique_fd>* apk_fds,
        std::vector<std::string>* dex_locations) {
    std::vector<std::string> classpaths_elems = base::Split(classpath, ":");
    for (const std::string& elem : classpaths_elems) {
        unique_fd fd(TEMP_FAILURE_RETRY(open(elem.c_str(), O_RDONLY)));
        if (fd < 0) {
            PLOG(ERROR) << "Could not open classpath elem " << elem;
            return false;
        } else {
            apk_fds->push_back(std::move(fd));
            dex_locations->push_back(elem);
        }
    }
    return true;
}

static bool create_app_profile_snapshot(int32_t app_id,
                                        const std::string& package_name,
                                        const std::string& profile_name,
                                        const std::string& classpath) {
    int app_shared_gid = multiuser_get_shared_gid(/*user_id*/ 0, app_id);

    unique_fd snapshot_fd = open_snapshot_profile(AID_SYSTEM, package_name, profile_name);
    if (snapshot_fd < 0) {
        return false;
    }

    std::vector<unique_fd> profiles_fd;
    unique_fd reference_profile_fd;
    open_profile_files(app_shared_gid, package_name, profile_name, /*is_secondary_dex*/ false,
            &profiles_fd, &reference_profile_fd);
    if (profiles_fd.empty() || (reference_profile_fd.get() < 0)) {
        return false;
    }

    profiles_fd.push_back(std::move(reference_profile_fd));

    // Open the class paths elements. These will be used to filter out profile data that does
    // not belong to the classpath during merge.
    std::vector<unique_fd> apk_fds;
    std::vector<std::string> dex_locations;
    if (!open_classpath_files(classpath, &apk_fds, &dex_locations)) {
        return false;
    }

    RunProfman args;
    // This is specifically a snapshot for an app, so don't use boot image profiles.
    args.SetupMerge(profiles_fd,
            snapshot_fd,
            apk_fds,
            dex_locations,
            /* for_snapshot= */ true,
            /* for_boot_image= */ false);
    pid_t pid = fork();
    if (pid == 0) {
        /* child -- drop privileges before continuing */
        drop_capabilities(app_shared_gid);
        args.Exec();
    }

    /* parent */
    int return_code = wait_child_with_timeout(pid, kShortTimeoutMs);
    if (!WIFEXITED(return_code)) {
        LOG(WARNING) << "profman failed for " << package_name << ":" << profile_name;
        cleanup_output_fd(snapshot_fd.get());
        return false;
    }

    // Verify that profman finished successfully.
    int profman_code = WEXITSTATUS(return_code);
    if (profman_code != PROFMAN_BIN_RETURN_CODE_SUCCESS) {
        LOG(WARNING) << "profman error for " << package_name << ":" << profile_name
                << ":" << profman_code;
        return false;
    }
    return true;
}

static bool create_boot_image_profile_snapshot(const std::string& package_name,
                                               const std::string& profile_name,
                                               const std::string& classpath) {
    // The reference profile directory for the android package might not be prepared. Do it now.
    const std::string ref_profile_dir =
            create_primary_reference_profile_package_dir_path(package_name);
    if (fs_prepare_dir(ref_profile_dir.c_str(), 0770, AID_SYSTEM, AID_SYSTEM) != 0) {
        PLOG(ERROR) << "Failed to prepare " << ref_profile_dir;
        return false;
    }

    // Return false for empty class path since it may otherwise return true below if profiles is
    // empty.
    if (classpath.empty()) {
        PLOG(ERROR) << "Class path is empty";
        return false;
    }

    // Open and create the snapshot profile.
    unique_fd snapshot_fd = open_snapshot_profile(AID_SYSTEM, package_name, profile_name);

    // Collect all non empty profiles.
    // The collection will traverse all applications profiles and find the non empty files.
    // This has the potential of inspecting a large number of files and directories (depending
    // on the number of applications and users). So there is a slight increase in the chance
    // to get get occasionally I/O errors (e.g. for opening the file). When that happens do not
    // fail the snapshot and aggregate whatever profile we could open.
    //
    // The profile snapshot is a best effort based on available data it's ok if some data
    // from some apps is missing. It will be counter productive for the snapshot to fail
    // because we could not open or read some of the files.
    std::vector<std::string> profiles;
    if (!collect_profiles(&profiles)) {
        LOG(WARNING) << "There were errors while collecting the profiles for the boot image.";
    }

    // If we have no profiles return early.
    if (profiles.empty()) {
        return true;
    }

    // Open the classpath elements. These will be used to filter out profile data that does
    // not belong to the classpath during merge.
    std::vector<unique_fd> apk_fds;
    std::vector<std::string> dex_locations;
    if (!open_classpath_files(classpath, &apk_fds, &dex_locations)) {
        return false;
    }

    // If we could not open any files from the classpath return an error.
    if (apk_fds.empty()) {
        LOG(ERROR) << "Could not open any of the classpath elements.";
        return false;
    }

    // Aggregate the profiles in batches of kAggregationBatchSize.
    // We do this to avoid opening a huge a amount of files.
    static constexpr size_t kAggregationBatchSize = 10;

    for (size_t i = 0; i < profiles.size(); )  {
        std::vector<unique_fd> profiles_fd;
        for (size_t k = 0; k < kAggregationBatchSize && i < profiles.size(); k++, i++) {
            unique_fd fd = open_profile(AID_SYSTEM, profiles[i], O_RDONLY, /*mode=*/ 0);
            if (fd.get() >= 0) {
                profiles_fd.push_back(std::move(fd));
            }
        }

        // We aggregate (read & write) into the same fd multiple times in a row.
        // We need to reset the cursor every time to ensure we read the whole file every time.
        if (TEMP_FAILURE_RETRY(lseek(snapshot_fd, 0, SEEK_SET)) == static_cast<off_t>(-1)) {
            PLOG(ERROR) << "Cannot reset position for snapshot profile";
            return false;
        }

        RunProfman args;
        args.SetupMerge(profiles_fd,
                        snapshot_fd,
                        apk_fds,
                        dex_locations,
                        /*for_snapshot=*/true,
                        /*for_boot_image=*/true);
        pid_t pid = fork();
        if (pid == 0) {
            /* child -- drop privileges before continuing */
            drop_capabilities(AID_SYSTEM);

            // The introduction of new access flags into boot jars causes them to
            // fail dex file verification.
            args.Exec();
        }

        /* parent */
        int return_code = wait_child_with_timeout(pid, kShortTimeoutMs);

        if (!WIFEXITED(return_code)) {
            PLOG(WARNING) << "profman failed for " << package_name << ":" << profile_name;
            cleanup_output_fd(snapshot_fd.get());
            return false;
        }

        // Verify that profman finished successfully.
        int profman_code = WEXITSTATUS(return_code);
        if (profman_code != PROFMAN_BIN_RETURN_CODE_SUCCESS) {
            LOG(WARNING) << "profman error for " << package_name << ":" << profile_name
                    << ":" << profman_code;
            return false;
        }
    }

    return true;
}

bool create_profile_snapshot(int32_t app_id, const std::string& package_name,
        const std::string& profile_name, const std::string& classpath) {
    if (app_id == -1) {
        return create_boot_image_profile_snapshot(package_name, profile_name, classpath);
    } else {
        return create_app_profile_snapshot(app_id, package_name, profile_name, classpath);
    }
}

static bool check_profile_exists_in_dexmetadata(const std::string& dex_metadata) {
    ZipArchiveHandle zip = nullptr;
    if (OpenArchive(dex_metadata.c_str(), &zip) != 0) {
        PLOG(ERROR) << "Failed to open dm '" << dex_metadata << "'";
        return false;
    }

    ZipEntry64 entry;
    int result = FindEntry(zip, "primary.prof", &entry);
    CloseArchive(zip);

    return result != 0 ? false : true;
}

bool prepare_app_profile(const std::string& package_name,
                         userid_t user_id,
                         appid_t app_id,
                         const std::string& profile_name,
                         const std::string& code_path,
                         const std::optional<std::string>& dex_metadata) {
    if (user_id != USER_NULL) {
        if (user_id < 0) {
            LOG(ERROR) << "Unexpected user ID " << user_id;
            return false;
        }

        // Prepare the current profile.
        std::string cur_profile = create_current_profile_path(user_id, package_name, profile_name,
                                                              /*is_secondary_dex*/ false);
        uid_t uid = multiuser_get_uid(user_id, app_id);
        if (fs_prepare_file_strict(cur_profile.c_str(), 0600, uid, uid) != 0) {
            PLOG(ERROR) << "Failed to prepare " << cur_profile;
            return false;
        }
    } else {
        // Prepare the reference profile as the system user.
        user_id = USER_SYSTEM;
    }

    // Check if we need to install the profile from the dex metadata.
    if (!dex_metadata || !check_profile_exists_in_dexmetadata(dex_metadata->c_str())) {
        return true;
    }

    // We have a dex metdata. Merge the profile into the reference profile.
    unique_fd ref_profile_fd =
            open_reference_profile(multiuser_get_uid(user_id, app_id), package_name, profile_name,
                                   /*read_write*/ true, /*is_secondary_dex*/ false);
    unique_fd dex_metadata_fd(TEMP_FAILURE_RETRY(
            open(dex_metadata->c_str(), O_RDONLY | O_NOFOLLOW)));
    unique_fd apk_fd(TEMP_FAILURE_RETRY(open(code_path.c_str(), O_RDONLY | O_NOFOLLOW)));
    if (apk_fd < 0) {
        PLOG(ERROR) << "Could not open code path " << code_path;
        return false;
    }

    RunProfman args;
    args.SetupCopyAndUpdate(dex_metadata_fd,
                            ref_profile_fd,
                            apk_fd,
                            code_path);
    pid_t pid = fork();
    if (pid == 0) {
        /* child -- drop privileges before continuing */
        gid_t app_shared_gid = multiuser_get_shared_gid(user_id, app_id);
        drop_capabilities(app_shared_gid);

        // The copy and update takes ownership over the fds.
        args.Exec();
    }

    /* parent */
    int return_code = wait_child_with_timeout(pid, kShortTimeoutMs);
    if (!WIFEXITED(return_code)) {
        PLOG(WARNING) << "profman failed for " << package_name << ":" << profile_name;
        cleanup_output_fd(ref_profile_fd.get());
        return false;
    }
    return true;
}

int get_odex_visibility(const char* apk_path, const char* instruction_set, const char* oat_dir) {
    char oat_path[PKG_PATH_MAX];
    if (!create_oat_out_path(apk_path, instruction_set, oat_dir, /*is_secondary_dex=*/false,
                             oat_path)) {
        return -1;
    }
    struct stat st;
    if (stat(oat_path, &st) == -1) {
        if (errno == ENOENT) {
            return ODEX_NOT_FOUND;
        }
        PLOG(ERROR) << "Could not stat " << oat_path;
        return -1;
    }
    return (st.st_mode & S_IROTH) ? ODEX_IS_PUBLIC : ODEX_IS_PRIVATE;
}

}  // namespace installd
}  // namespace android
