/**
 * Copyright (c) 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "dumpstate"

#include "DumpstateService.h"

#include <memory>

#include <android-base/stringprintf.h>
#include "android/os/BnDumpstate.h"

#include "DumpstateInternal.h"

using android::base::StringPrintf;

namespace android {
namespace os {

namespace {

struct DumpstateInfo {
  public:
    Dumpstate* ds = nullptr;
    int32_t calling_uid = -1;
    std::string calling_package;
};

static binder::Status exception(uint32_t code, const std::string& msg,
                                const std::string& extra_msg = "") {
    if (extra_msg.empty()) {
        MYLOGE("%s (%d) ", msg.c_str(), code);
    } else {
        MYLOGE("%s %s (%d) ", msg.c_str(), extra_msg.c_str(), code);
    }
    return binder::Status::fromExceptionCode(code, String8(msg.c_str()));
}

// Creates a bugreport and exits, thus preserving the oneshot nature of the service.
// Note: takes ownership of data.
[[noreturn]] static void* dumpstate_thread_main(void* data) {
    std::unique_ptr<DumpstateInfo> ds_info(static_cast<DumpstateInfo*>(data));
    ds_info->ds->Run(ds_info->calling_uid, ds_info->calling_package);
    MYLOGD("Finished taking a bugreport. Exiting.\n");
    exit(0);
}

[[noreturn]] static void signalErrorAndExit(sp<IDumpstateListener> listener, int error_code) {
    listener->onError(error_code);
    exit(0);
}

}  // namespace

DumpstateService::DumpstateService() : ds_(nullptr), calling_uid_(-1), calling_package_() {
}

char const* DumpstateService::getServiceName() {
    return "dumpstate";
}

status_t DumpstateService::Start() {
    IPCThreadState::self()->disableBackgroundScheduling(true);
    status_t ret = BinderService<DumpstateService>::publish();
    if (ret != android::OK) {
        return ret;
    }
    sp<ProcessState> ps(ProcessState::self());
    ps->startThreadPool();
    ps->giveThreadPoolName();
    return android::OK;
}

binder::Status DumpstateService::startBugreport(int32_t calling_uid,
                                                const std::string& calling_package,
                                                android::base::unique_fd bugreport_fd,
                                                android::base::unique_fd screenshot_fd,
                                                int bugreport_mode,
                                                const sp<IDumpstateListener>& listener,
                                                bool is_screenshot_requested) {
    MYLOGI("startBugreport() with mode: %d\n", bugreport_mode);

    // Ensure there is only one bugreport in progress at a time.
    std::lock_guard<std::mutex> lock(lock_);
    if (ds_ != nullptr) {
        MYLOGE("Error! There is already a bugreport in progress. Returning.");
        if (listener != nullptr) {
            listener->onError(IDumpstateListener::BUGREPORT_ERROR_ANOTHER_REPORT_IN_PROGRESS);
        }
        return exception(binder::Status::EX_SERVICE_SPECIFIC,
                         "There is already a bugreport in progress");
    }

    // From here on, all conditions that indicate we are done with this incoming request should
    // result in exiting the service to free it up for next invocation.
    if (listener == nullptr) {
        MYLOGE("Invalid input: no listener");
        exit(0);
    }

    if (bugreport_mode != Dumpstate::BugreportMode::BUGREPORT_FULL &&
        bugreport_mode != Dumpstate::BugreportMode::BUGREPORT_INTERACTIVE &&
        bugreport_mode != Dumpstate::BugreportMode::BUGREPORT_REMOTE &&
        bugreport_mode != Dumpstate::BugreportMode::BUGREPORT_WEAR &&
        bugreport_mode != Dumpstate::BugreportMode::BUGREPORT_TELEPHONY &&
        bugreport_mode != Dumpstate::BugreportMode::BUGREPORT_WIFI &&
        bugreport_mode != Dumpstate::BugreportMode::BUGREPORT_DEFAULT) {
        MYLOGE("Invalid input: bad bugreport mode: %d", bugreport_mode);
        signalErrorAndExit(listener, IDumpstateListener::BUGREPORT_ERROR_INVALID_INPUT);
    }

    std::unique_ptr<Dumpstate::DumpOptions> options = std::make_unique<Dumpstate::DumpOptions>();
    options->Initialize(static_cast<Dumpstate::BugreportMode>(bugreport_mode), bugreport_fd,
                        screenshot_fd, is_screenshot_requested);

    if (bugreport_fd.get() == -1 || (options->do_screenshot && screenshot_fd.get() == -1)) {
        MYLOGE("Invalid filedescriptor");
        signalErrorAndExit(listener, IDumpstateListener::BUGREPORT_ERROR_INVALID_INPUT);
    }


    ds_ = &(Dumpstate::GetInstance());
    ds_->SetOptions(std::move(options));
    ds_->listener_ = listener;

    // Track caller info for cancellation purposes.
    calling_uid_ = calling_uid;
    calling_package_ = calling_package;

    DumpstateInfo* ds_info = new DumpstateInfo();
    ds_info->ds = ds_;
    ds_info->calling_uid = calling_uid;
    ds_info->calling_package = calling_package;

    pthread_t thread;
    // Initialize dumpstate
    ds_->Initialize();
    status_t err = pthread_create(&thread, nullptr, dumpstate_thread_main, ds_info);
    if (err != 0) {
        delete ds_info;
        ds_info = nullptr;
        MYLOGE("Could not create a thread");
        signalErrorAndExit(listener, IDumpstateListener::BUGREPORT_ERROR_RUNTIME_ERROR);
    }
    return binder::Status::ok();
}

binder::Status DumpstateService::cancelBugreport(int32_t calling_uid,
                                                 const std::string& calling_package) {
    std::lock_guard<std::mutex> lock(lock_);
    if (calling_uid != calling_uid_ || calling_package != calling_package_) {
        // Note: we use a SecurityException to prevent BugreportManagerServiceImpl from killing the
        // report in progress (from another caller).
        return exception(
            binder::Status::EX_SECURITY,
            StringPrintf("Cancellation requested by %d/%s does not match report in "
                         "progress",
                         calling_uid, calling_package.c_str()),
            // Sharing the owner of the BR is a (minor) leak, so leave it out of the app's exception
            StringPrintf("started by %d/%s", calling_uid_, calling_package_.c_str()));
    }
    ds_->Cancel();
    return binder::Status::ok();
}

status_t DumpstateService::dump(int fd, const Vector<String16>&) {
    std::lock_guard<std::mutex> lock(lock_);
    if (ds_ == nullptr) {
        dprintf(fd, "Bugreport not in progress yet");
        return NO_ERROR;
    }
    std::string destination = ds_->options_->bugreport_fd.get() != -1
                                  ? StringPrintf("[fd:%d]", ds_->options_->bugreport_fd.get())
                                  : ds_->bugreport_internal_dir_.c_str();
    dprintf(fd, "id: %d\n", ds_->id_);
    dprintf(fd, "pid: %d\n", ds_->pid_);
    dprintf(fd, "update_progress: %s\n", ds_->options_->do_progress_updates ? "true" : "false");
    dprintf(fd, "last_percent_progress: %d\n", ds_->last_reported_percent_progress_);
    dprintf(fd, "progress:\n");
    ds_->progress_->Dump(fd, "  ");
    dprintf(fd, "args: %s\n", ds_->options_->args.c_str());
    dprintf(fd, "bugreport_mode: %s\n", ds_->options_->bugreport_mode.c_str());
    dprintf(fd, "version: %s\n", ds_->version_.c_str());
    dprintf(fd, "bugreport_dir: %s\n", destination.c_str());
    dprintf(fd, "screenshot_path: %s\n", ds_->screenshot_path_.c_str());
    dprintf(fd, "log_path: %s\n", ds_->log_path_.c_str());
    dprintf(fd, "tmp_path: %s\n", ds_->tmp_path_.c_str());
    dprintf(fd, "path: %s\n", ds_->path_.c_str());
    dprintf(fd, "base_name: %s\n", ds_->base_name_.c_str());
    dprintf(fd, "name: %s\n", ds_->name_.c_str());
    dprintf(fd, "now: %ld\n", ds_->now_);
    dprintf(fd, "is_zipping: %s\n", ds_->IsZipping() ? "true" : "false");
    dprintf(fd, "notification title: %s\n", ds_->options_->notification_title.c_str());
    dprintf(fd, "notification description: %s\n", ds_->options_->notification_description.c_str());

    return NO_ERROR;
}
}  // namespace os
}  // namespace android
