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

#ifndef FRAMEWORK_NATIVE_CMD_TASKQUEUE_H_
#define FRAMEWORK_NATIVE_CMD_TASKQUEUE_H_

#include <mutex>
#include <queue>

#include <android-base/macros.h>

namespace android {
namespace os {
namespace dumpstate {

/*
 * A task queue for dumpstate to collect tasks such as adding file to the zip
 * which are needed to run in a single thread. The task is a callable function
 * included a cancel task boolean parameter. The TaskQueue could
 * cancel the task in the destructor if the task has never been called.
 */
class TaskQueue {
  public:
    TaskQueue() = default;
    ~TaskQueue();

    /*
     * Adds a task into the queue.
     *
     * |f| Callable function to execute the task. The function must include a
     *     boolean parameter for TaskQueue to notify whether the task is
     *     cancelled or not.
     * |args| A list of arguments.
     */
    template<class F, class... Args> void add(F&& f, Args&&... args) {
        auto func = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
        std::unique_lock lock(lock_);
        tasks_.emplace([=](bool cancelled) {
            std::invoke(func, cancelled);
        });
    }

    /*
     * Invokes all tasks in the task queue.
     *
     * |do_cancel| true to cancel all tasks in the queue.
     */
    void run(bool do_cancel);

  private:
    using Task = std::function<void(bool)>;

    std::mutex lock_;
    std::queue<Task> tasks_;

    DISALLOW_COPY_AND_ASSIGN(TaskQueue);
};

}  // namespace dumpstate
}  // namespace os
}  // namespace android

#endif //FRAMEWORK_NATIVE_CMD_TASKQUEUE_H_
