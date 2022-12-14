/*
 ** Copyright 2016, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#include <fcntl.h>
#include <linux/unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <array>
#include <fstream>
#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <libdm/dm.h>
#include <selinux/android.h>

#include "installd_constants.h"
#include "otapreopt_utils.h"

#ifndef LOG_TAG
#define LOG_TAG "otapreopt"
#endif

using android::base::StringPrintf;

namespace android {
namespace installd {

static void CloseDescriptor(int fd) {
    if (fd >= 0) {
        int result = close(fd);
        UNUSED(result);  // Ignore result. Printing to logcat will open a new descriptor
                         // that we do *not* want.
    }
}

static void CloseDescriptor(const char* descriptor_string) {
    int fd = -1;
    std::istringstream stream(descriptor_string);
    stream >> fd;
    if (!stream.fail()) {
        CloseDescriptor(fd);
    }
}

static void ActivateApexPackages() {
    std::vector<std::string> apexd_cmd{"/system/bin/apexd", "--otachroot-bootstrap"};
    std::string apexd_error_msg;

    bool exec_result = Exec(apexd_cmd, &apexd_error_msg);
    if (!exec_result) {
        PLOG(ERROR) << "Running otapreopt failed: " << apexd_error_msg;
        exit(220);
    }
}

static void DeactivateApexPackages() {
    std::vector<std::string> apexd_cmd{"/system/bin/apexd", "--unmount-all"};
    std::string apexd_error_msg;
    bool exec_result = Exec(apexd_cmd, &apexd_error_msg);
    if (!exec_result) {
        PLOG(ERROR) << "Running /system/bin/apexd --unmount-all failed: " << apexd_error_msg;
    }
}

static void TryExtraMount(const char* name, const char* slot, const char* target) {
    std::string partition_name = StringPrintf("%s%s", name, slot);

    // See whether update_engine mounted a logical partition.
    {
        auto& dm = dm::DeviceMapper::Instance();
        if (dm.GetState(partition_name) != dm::DmDeviceState::INVALID) {
            std::string path;
            if (dm.GetDmDevicePathByName(partition_name, &path)) {
                int mount_result = mount(path.c_str(),
                                         target,
                                         "ext4",
                                         MS_RDONLY,
                                         /* data */ nullptr);
                if (mount_result == 0) {
                    return;
                }
            }
        }
    }

    // Fall back and attempt a direct mount.
    std::string block_device = StringPrintf("/dev/block/by-name/%s", partition_name.c_str());
    int mount_result = mount(block_device.c_str(),
                             target,
                             "ext4",
                             MS_RDONLY,
                             /* data */ nullptr);
    UNUSED(mount_result);
}

// Entry for otapreopt_chroot. Expected parameters are:
//   [cmd] [status-fd] [target-slot] "dexopt" [dexopt-params]
// The file descriptor denoted by status-fd will be closed. The rest of the parameters will
// be passed on to otapreopt in the chroot.
static int otapreopt_chroot(const int argc, char **arg) {
    // Validate arguments
    // We need the command, status channel and target slot, at a minimum.
    if(argc < 3) {
        PLOG(ERROR) << "Not enough arguments.";
        exit(208);
    }
    // Close all file descriptors. They are coming from the caller, we do not want to pass them
    // on across our fork/exec into a different domain.
    // 1) Default descriptors.
    CloseDescriptor(STDIN_FILENO);
    CloseDescriptor(STDOUT_FILENO);
    CloseDescriptor(STDERR_FILENO);
    // 2) The status channel.
    CloseDescriptor(arg[1]);

    // We need to run the otapreopt tool from the postinstall partition. As such, set up a
    // mount namespace and change root.

    // Create our own mount namespace.
    if (unshare(CLONE_NEWNS) != 0) {
        PLOG(ERROR) << "Failed to unshare() for otapreopt.";
        exit(200);
    }

    // Make postinstall private, so that our changes don't propagate.
    if (mount("", "/postinstall", nullptr, MS_PRIVATE, nullptr) != 0) {
        PLOG(ERROR) << "Failed to mount private.";
        exit(201);
    }

    // Bind mount necessary directories.
    constexpr const char* kBindMounts[] = {
            "/data", "/dev", "/proc", "/sys"
    };
    for (size_t i = 0; i < arraysize(kBindMounts); ++i) {
        std::string trg = StringPrintf("/postinstall%s", kBindMounts[i]);
        if (mount(kBindMounts[i], trg.c_str(), nullptr, MS_BIND, nullptr) != 0) {
            PLOG(ERROR) << "Failed to bind-mount " << kBindMounts[i];
            exit(202);
        }
    }

    // Try to mount the vendor partition. update_engine doesn't do this for us, but we
    // want it for vendor APKs.
    // Notes:
    //  1) We pretty much guess a name here and hope to find the partition by name.
    //     It is just as complicated and brittle to scan /proc/mounts. But this requires
    //     validating the target-slot so as not to try to mount some totally random path.
    //  2) We're in a mount namespace here, so when we die, this will be cleaned up.
    //  3) Ignore errors. Printing anything at this stage will open a file descriptor
    //     for logging.
    if (!ValidateTargetSlotSuffix(arg[2])) {
        LOG(ERROR) << "Target slot suffix not legal: " << arg[2];
        exit(207);
    }
    TryExtraMount("vendor", arg[2], "/postinstall/vendor");

    // Try to mount the product partition. update_engine doesn't do this for us, but we
    // want it for product APKs. Same notes as vendor above.
    TryExtraMount("product", arg[2], "/postinstall/product");

    // Try to mount the system_ext partition. update_engine doesn't do this for
    // us, but we want it for system_ext APKs. Same notes as vendor and product
    // above.
    TryExtraMount("system_ext", arg[2], "/postinstall/system_ext");

    constexpr const char* kPostInstallLinkerconfig = "/postinstall/linkerconfig";
    // Try to mount /postinstall/linkerconfig. we will set it up after performing the chroot
    if (mount("tmpfs", kPostInstallLinkerconfig, "tmpfs", 0, nullptr) != 0) {
        PLOG(ERROR) << "Failed to mount a tmpfs for " << kPostInstallLinkerconfig;
        exit(215);
    }

    // Setup APEX mount point and its security context.
    static constexpr const char* kPostinstallApexDir = "/postinstall/apex";
    // The following logic is similar to the one in system/core/rootdir/init.rc:
    //
    //   mount tmpfs tmpfs /apex nodev noexec nosuid
    //   chmod 0755 /apex
    //   chown root root /apex
    //   restorecon /apex
    //
    // except we perform the `restorecon` step just after mounting the tmpfs
    // filesystem in /postinstall/apex, so that this directory is correctly
    // labeled (with type `postinstall_apex_mnt_dir`) and may be manipulated in
    // following operations (`chmod`, `chown`, etc.) following policies
    // restricted to `postinstall_apex_mnt_dir`:
    //
    //   mount tmpfs tmpfs /postinstall/apex nodev noexec nosuid
    //   restorecon /postinstall/apex
    //   chmod 0755 /postinstall/apex
    //   chown root root /postinstall/apex
    //
    if (mount("tmpfs", kPostinstallApexDir, "tmpfs", MS_NODEV | MS_NOEXEC | MS_NOSUID, nullptr)
        != 0) {
        PLOG(ERROR) << "Failed to mount tmpfs in " << kPostinstallApexDir;
        exit(209);
    }
    if (selinux_android_restorecon(kPostinstallApexDir, 0) < 0) {
        PLOG(ERROR) << "Failed to restorecon " << kPostinstallApexDir;
        exit(214);
    }
    if (chmod(kPostinstallApexDir, 0755) != 0) {
        PLOG(ERROR) << "Failed to chmod " << kPostinstallApexDir << " to 0755";
        exit(210);
    }
    if (chown(kPostinstallApexDir, 0, 0) != 0) {
        PLOG(ERROR) << "Failed to chown " << kPostinstallApexDir << " to root:root";
        exit(211);
    }

    // Chdir into /postinstall.
    if (chdir("/postinstall") != 0) {
        PLOG(ERROR) << "Unable to chdir into /postinstall.";
        exit(203);
    }

    // Make /postinstall the root in our mount namespace.
    if (chroot(".")  != 0) {
        PLOG(ERROR) << "Failed to chroot";
        exit(204);
    }

    if (chdir("/") != 0) {
        PLOG(ERROR) << "Unable to chdir into /.";
        exit(205);
    }

    // Call apexd --unmount-all to free up loop and dm block devices, so that we can re-use
    // them during the next invocation. Since otapreopt_chroot calls exit in case something goes
    // wrong we need to register our own atexit handler.
    // We want to register this handler before actually activating apex packages. This is mostly
    // due to the fact that if fail to unmount apexes, then on the next run of otapreopt_chroot
    // we will ask for new loop devices instead of re-using existing ones, and we really don't want
    // to do that. :)
    if (atexit(DeactivateApexPackages) != 0) {
        LOG(ERROR) << "Failed to register atexit hander";
        exit(206);
    }

    // Try to mount APEX packages in "/apex" in the chroot dir. We need at least
    // the ART APEX, as it is required by otapreopt to run dex2oat.
    ActivateApexPackages();

    auto cleanup = android::base::make_scope_guard([](){
        std::vector<std::string> apexd_cmd{"/system/bin/apexd", "--unmount-all"};
        std::string apexd_error_msg;
        bool exec_result = Exec(apexd_cmd, &apexd_error_msg);
        if (!exec_result) {
            PLOG(ERROR) << "Running /system/bin/apexd --unmount-all failed: " << apexd_error_msg;
        }
    });
    // Check that an ART APEX has been activated; clean up and exit
    // early otherwise.
    static constexpr const std::string_view kRequiredApexs[] = {
      "com.android.art",
      "com.android.runtime",
      "com.android.sdkext",  // For derive_classpath
    };
    std::array<bool, arraysize(kRequiredApexs)> found_apexs{ false, false };
    DIR* apex_dir = opendir("/apex");
    if (apex_dir == nullptr) {
        PLOG(ERROR) << "unable to open /apex";
        exit(220);
    }
    for (dirent* entry = readdir(apex_dir); entry != nullptr; entry = readdir(apex_dir)) {
        for (int i = 0; i < found_apexs.size(); i++) {
            if (kRequiredApexs[i] == std::string_view(entry->d_name)) {
                found_apexs[i] = true;
                break;
            }
        }
    }
    closedir(apex_dir);
    auto it = std::find(found_apexs.cbegin(), found_apexs.cend(), false);
    if (it != found_apexs.cend()) {
        LOG(ERROR) << "No activated " << kRequiredApexs[std::distance(found_apexs.cbegin(), it)]
                   << " package!";
        exit(221);
    }

    // Setup /linkerconfig. Doing it after the chroot means it doesn't need its own category
    if (selinux_android_restorecon("/linkerconfig", 0) < 0) {
        PLOG(ERROR) << "Failed to restorecon /linkerconfig";
        exit(219);
    }
    std::vector<std::string> linkerconfig_cmd{"/apex/com.android.runtime/bin/linkerconfig",
                                              "--target", "/linkerconfig"};
    std::string linkerconfig_error_msg;
    bool linkerconfig_exec_result = Exec(linkerconfig_cmd, &linkerconfig_error_msg);
    if (!linkerconfig_exec_result) {
        LOG(ERROR) << "Running linkerconfig failed: " << linkerconfig_error_msg;
        exit(218);
    }

    // Now go on and run otapreopt.

    // Incoming:  cmd + status-fd + target-slot + cmd...      | Incoming | = argc
    // Outgoing:  cmd             + target-slot + cmd...      | Outgoing | = argc - 1
    std::vector<std::string> cmd;
    cmd.reserve(argc);
    cmd.push_back("/system/bin/otapreopt");

    // The first parameter is the status file descriptor, skip.
    for (size_t i = 2; i < static_cast<size_t>(argc); ++i) {
        cmd.push_back(arg[i]);
    }

    // Fork and execute otapreopt in its own process.
    std::string error_msg;
    bool exec_result = Exec(cmd, &error_msg);
    if (!exec_result) {
        LOG(ERROR) << "Running otapreopt failed: " << error_msg;
    }

    if (!exec_result) {
        exit(213);
    }

    return 0;
}

}  // namespace installd
}  // namespace android

int main(const int argc, char *argv[]) {
    return android::installd::otapreopt_chroot(argc, argv);
}
