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

#pragma once

#include <list>
#include <memory>
#include <mutex>

#include "LogBuffer.h"
#include "LogReaderThread.h"
#include "LogdLock.h"

class LogReaderList {
  public:
    void NotifyNewLog(LogMask log_mask) const REQUIRES(logd_lock);

    std::list<std::unique_ptr<LogReaderThread>>& reader_threads() REQUIRES(logd_lock) {
        return reader_threads_;
    }

  private:
    std::list<std::unique_ptr<LogReaderThread>> reader_threads_ GUARDED_BY(logd_lock);
};