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

#ifndef FRAMEWORK_NATIVE_CMD_DUMPPOOL_H_
#define FRAMEWORK_NATIVE_CMD_DUMPPOOL_H_

#include <future>
#include <queue>
#include <string>

#include <android-base/file.h>
#include <android-base/macros.h>

namespace android {
namespace os {
namespace dumpstate {

class DumpPoolTest;

/*
 * Waits until the task is finished. Dumps the task results to the specified
 * out_fd.
 *
 * |future| The task future.
 * |title| Dump title string to the out_fd, an empty string for nothing.
 * |out_fd| The target file to dump the result from the task.
 */
void WaitForTask(std::future<std::string> future, const std::string& title, int out_fd);

/*
 * Waits until the task is finished. Dumps the task results to the STDOUT_FILENO.
 */

inline void WaitForTask(std::future<std::string> future) {
    WaitForTask(std::move(future), "", STDOUT_FILENO);
}

/*
 * A thread pool with the fixed number of threads to execute multiple dump tasks
 * simultaneously for dumpstate. The dump task is a callable function. It
 * could include a file descriptor as a parameter to redirect dump results, if
 * it needs to output results to the bugreport. This can avoid messing up
 * bugreport's results when multiple dump tasks are running at the same time.
 * Takes an example below for the usage of the DumpPool:
 *
 * void DumpFoo(int out_fd) {
 *     dprintf(out_fd, "Dump result to out_fd ...");
 * }
 * ...
 * DumpPool pool(tmp_root);
 * auto task = pool.enqueueTaskWithFd("TaskName", &DumpFoo, std::placeholders::_1);
 * ...
 * WaitForTask(task);
 *
 * DumpFoo is a callable function included a out_fd parameter. Using the
 * enqueueTaskWithFd method in DumpPool to enqueue the task to the pool. The
 * std::placeholders::_1 is a placeholder for DumpPool to pass a fd argument.
 *
 * std::futures returned by `enqueueTask*()` must all have their `get` methods
 * called, or have been destroyed before the DumpPool itself is destroyed.
 */
class DumpPool {
  friend class android::os::dumpstate::DumpPoolTest;

  public:
    /*
     * Creates a thread pool.
     *
     * |tmp_root| A path to a temporary folder for threads to create temporary
     * files.
     */
    explicit DumpPool(const std::string& tmp_root);

    /*
     * Will waits until all threads exit the loop. Destroying DumpPool before destroying the
     * associated std::futures created by `enqueueTask*` will cause an abort on Android because
     * Android is built with `-fno-exceptions`.
     */
    ~DumpPool();

    /*
     * Starts the threads in the pool.
     *
     * |thread_counts| the number of threads to start.
     */
    void start(int thread_counts = MAX_THREAD_COUNT);

    /*
     * Adds a task into the queue of the thread pool.
     *
     * |duration_title| The name of the task. It's also the title of the
     * DurationReporter log.
     * |f| Callable function to execute the task.
     * |args| A list of arguments.
     *
     * TODO(b/164369078): remove this api to have just one enqueueTask for consistency.
     */
    template<class F, class... Args>
    std::future<std::string> enqueueTask(const std::string& duration_title, F&& f, Args&&... args) {
        std::function<void(void)> func = std::bind(std::forward<F>(f),
                std::forward<Args>(args)...);
        auto future = post(duration_title, func);
        if (threads_.empty()) {
            start();
        }
        return future;
    }

    /*
     * Adds a task into the queue of the thread pool. The task takes a file
     * descriptor as a parameter to redirect dump results to a temporary file.
     *
     * |duration_title| The title of the DurationReporter log.
     * |f| Callable function to execute the task.
     * |args| A list of arguments. A placeholder std::placeholders::_1 as a fd
     * argument needs to be included here.
     */
    template<class F, class... Args> std::future<std::string> enqueueTaskWithFd(
            const std::string& duration_title, F&& f, Args&&... args) {
        std::function<void(int)> func = std::bind(std::forward<F>(f),
                std::forward<Args>(args)...);
        auto future = post(duration_title, func);
        if (threads_.empty()) {
            start();
        }
        return future;
    }

    /*
     * Deletes temporary files created by DumpPool.
     */
    void deleteTempFiles();

    static const std::string PREFIX_TMPFILE_NAME;

  private:
    using Task = std::packaged_task<std::string()>;

    template<class T> void invokeTask(T dump_func, const std::string& duration_title, int out_fd);

    template<class T>
    std::future<std::string> post(const std::string& duration_title, T dump_func) {
        Task packaged_task([=]() {
            std::unique_ptr<TmpFile> tmp_file_ptr = createTempFile();
            if (!tmp_file_ptr) {
                return std::string("");
            }
            invokeTask(dump_func, duration_title, tmp_file_ptr->fd.get());
            fsync(tmp_file_ptr->fd.get());
            return std::string(tmp_file_ptr->path);
        });
        std::unique_lock lock(lock_);
        auto future = packaged_task.get_future();
        tasks_.push(std::move(packaged_task));
        condition_variable_.notify_one();
        return future;
    }

    typedef struct {
      android::base::unique_fd fd;
      char path[1024];
    } TmpFile;

    std::unique_ptr<TmpFile> createTempFile();
    void deleteTempFiles(const std::string& folder);
    void setThreadName(const pthread_t thread, int id);
    void loop();

    /*
     * For test purpose only. Enables or disables logging duration of the task.
     *
     * |log_duration| if true, DurationReporter is initiated to log duration of
     * the task.
     */
    void setLogDuration(bool log_duration);

  private:
    static const int MAX_THREAD_COUNT = 4;

    /* A path to a temporary folder for threads to create temporary files. */
    std::string tmp_root_;
    bool shutdown_;
    bool log_duration_; // For test purpose only, the default value is true.
    std::mutex lock_;  // A lock for the tasks_.
    std::condition_variable condition_variable_;

    std::vector<std::thread> threads_;
    std::queue<Task> tasks_;

    DISALLOW_COPY_AND_ASSIGN(DumpPool);
};

}  // namespace dumpstate
}  // namespace os
}  // namespace android

#endif //FRAMEWORK_NATIVE_CMD_DUMPPOOL_H_
