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

#define LOG_TAG "dumpstate"

#include "DumpPool.h"

#include <array>
#include <thread>

#include <log/log.h>

#include "dumpstate.h"
#include "DumpstateInternal.h"
#include "DumpstateUtil.h"

namespace android {
namespace os {
namespace dumpstate {

const std::string DumpPool::PREFIX_TMPFILE_NAME = "dump-tmp.";

DumpPool::DumpPool(const std::string& tmp_root) : tmp_root_(tmp_root), shutdown_(false),
        log_duration_(true) {
    assert(!tmp_root.empty());
    deleteTempFiles(tmp_root_);
}

DumpPool::~DumpPool() {
    shutdown();
}

void DumpPool::start(int thread_counts) {
    assert(thread_counts > 0);
    assert(threads_.empty());
    if (thread_counts > MAX_THREAD_COUNT) {
        thread_counts = MAX_THREAD_COUNT;
    }
    MYLOGI("Start thread pool:%d", thread_counts);
    shutdown_ = false;
    for (int i = 0; i < thread_counts; i++) {
        threads_.emplace_back(std::thread([=]() {
            setThreadName(pthread_self(), i + 1);
            loop();
        }));
    }
}

void DumpPool::shutdown() {
    std::unique_lock lock(lock_);
    if (shutdown_ || threads_.empty()) {
        return;
    }
    futures_map_.clear();
    while (!tasks_.empty()) tasks_.pop();

    shutdown_ = true;
    condition_variable_.notify_all();
    lock.unlock();

    for (auto& thread : threads_) {
        thread.join();
    }
    threads_.clear();
    deleteTempFiles(tmp_root_);
    MYLOGI("shutdown thread pool");
}

void DumpPool::waitForTask(const std::string& task_name, const std::string& title,
        int out_fd) {
    DurationReporter duration_reporter("Wait for " + task_name, true);
    auto iterator = futures_map_.find(task_name);
    if (iterator == futures_map_.end()) {
        MYLOGW("Task %s does not exist", task_name.c_str());
        return;
    }
    Future future = iterator->second;
    futures_map_.erase(iterator);

    std::string result = future.get();
    if (result.empty()) {
        return;
    }
    DumpFileToFd(out_fd, title, result);
    if (unlink(result.c_str())) {
        MYLOGE("Failed to unlink (%s): %s\n", result.c_str(), strerror(errno));
    }
}

void DumpPool::deleteTempFiles() {
    deleteTempFiles(tmp_root_);
}

void DumpPool::setLogDuration(bool log_duration) {
    log_duration_ = log_duration;
}

template <>
void DumpPool::invokeTask<std::function<void()>>(std::function<void()> dump_func,
        const std::string& duration_title, int out_fd) {
    DurationReporter duration_reporter(duration_title, /*logcat_only =*/!log_duration_,
            /*verbose =*/false, out_fd);
    std::invoke(dump_func);
}

template <>
void DumpPool::invokeTask<std::function<void(int)>>(std::function<void(int)> dump_func,
        const std::string& duration_title, int out_fd) {
    DurationReporter duration_reporter(duration_title, /*logcat_only =*/!log_duration_,
            /*verbose =*/false, out_fd);
    std::invoke(dump_func, out_fd);
}

std::unique_ptr<DumpPool::TmpFile> DumpPool::createTempFile() {
    auto tmp_file_ptr = std::make_unique<TmpFile>();
    std::string file_name_format = "%s/" + PREFIX_TMPFILE_NAME + "XXXXXX";
    snprintf(tmp_file_ptr->path, sizeof(tmp_file_ptr->path), file_name_format.c_str(),
             tmp_root_.c_str());
    tmp_file_ptr->fd.reset(TEMP_FAILURE_RETRY(
            mkostemp(tmp_file_ptr->path, O_CLOEXEC)));
    if (tmp_file_ptr->fd.get() == -1) {
        MYLOGE("open(%s, %s)\n", tmp_file_ptr->path, strerror(errno));
        tmp_file_ptr = nullptr;
        return tmp_file_ptr;
    }
    return tmp_file_ptr;
}

void DumpPool::deleteTempFiles(const std::string& folder) {
    std::unique_ptr<DIR, decltype(&closedir)> dir_ptr(opendir(folder.c_str()),
            &closedir);
    if (!dir_ptr) {
        MYLOGE("Failed to opendir (%s): %s\n", folder.c_str(), strerror(errno));
        return;
    }
    int dir_fd = dirfd(dir_ptr.get());
    if (dir_fd < 0) {
        MYLOGE("Failed to get fd of dir (%s): %s\n", folder.c_str(),
               strerror(errno));
        return;
    }

    struct dirent* de;
    while ((de = readdir(dir_ptr.get()))) {
        if (de->d_type != DT_REG) {
            continue;
        }
        std::string file_name(de->d_name);
        if (file_name.find(PREFIX_TMPFILE_NAME) != 0) {
            continue;
        }
        if (unlinkat(dir_fd, file_name.c_str(), 0)) {
            MYLOGE("Failed to unlink (%s): %s\n", file_name.c_str(),
                   strerror(errno));
        }
    }
}

void DumpPool::setThreadName(const pthread_t thread, int id) {
    std::array<char, 15> name;
    snprintf(name.data(), name.size(), "dumpstate_%d", id);
    pthread_setname_np(thread, name.data());
}

void DumpPool::loop() {
    std::unique_lock lock(lock_);
    while (!shutdown_) {
        if (tasks_.empty()) {
            condition_variable_.wait(lock);
            continue;
        } else {
            std::packaged_task<std::string()> task = std::move(tasks_.front());
            tasks_.pop();
            lock.unlock();
            std::invoke(task);
            lock.lock();
        }
    }
}

}  // namespace dumpstate
}  // namespace os
}  // namespace android
