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

#include <chrono>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "ChattyLogBuffer.h"
#include "LogBuffer.h"
#include "LogReaderList.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "PruneList.h"
#include "SerializedLogBuffer.h"
#include "SimpleLogBuffer.h"

using namespace std::chrono_literals;

struct LogMessage {
    logger_entry entry;
    std::string message;
    bool regex_compare = false;  // Only set for expected messages, when true 'message' should be
                                 // interpretted as a regex.
};

// Compares the ordered list of expected and result, causing a test failure with appropriate
// information on failure.
void CompareLogMessages(const std::vector<LogMessage>& expected,
                        const std::vector<LogMessage>& result);
// Sets hdr_size and len parameters appropriately.
void FixupMessages(std::vector<LogMessage>* messages);

class TestWriter : public LogWriter {
  public:
    TestWriter(std::vector<LogMessage>* msgs, bool* released)
        : LogWriter(0, true), msgs_(msgs), released_(released) {}
    bool Write(const logger_entry& entry, const char* message) override {
        msgs_->emplace_back(LogMessage{entry, std::string(message, entry.len), false});
        return true;
    }

    void Release() {
        if (released_) *released_ = true;
    }

    std::string name() const override { return "test_writer"; }

  private:
    std::vector<LogMessage>* msgs_;
    bool* released_;
};

class LogBufferTest : public testing::TestWithParam<std::string> {
  protected:
    void SetUp() override {
        if (GetParam() == "chatty") {
            log_buffer_.reset(new ChattyLogBuffer(&reader_list_, &tags_, &prune_, &stats_));
        } else if (GetParam() == "serialized") {
            log_buffer_.reset(new SerializedLogBuffer(&reader_list_, &tags_, &stats_));
        } else if (GetParam() == "simple") {
            log_buffer_.reset(new SimpleLogBuffer(&reader_list_, &tags_, &stats_));
        } else {
            FAIL() << "Unknown buffer type selected for test";
        }

        log_id_for_each(i) { log_buffer_->SetSize(i, 1024 * 1024); }
    }

    void LogMessages(const std::vector<LogMessage>& messages) {
        for (auto& [entry, message, _] : messages) {
            EXPECT_GT(log_buffer_->Log(static_cast<log_id_t>(entry.lid),
                                       log_time(entry.sec, entry.nsec), entry.uid, entry.pid,
                                       entry.tid, message.c_str(), message.size()),
                      0);
        }
    }

    struct FlushMessagesResult {
        std::vector<LogMessage> messages;
        uint64_t next_sequence;
    };

    FlushMessagesResult FlushMessages(uint64_t sequence = 1, LogMask log_mask = kLogMaskAll) {
        std::vector<LogMessage> read_log_messages;
        auto lock = std::lock_guard{logd_lock};
        std::unique_ptr<LogWriter> test_writer(new TestWriter(&read_log_messages, nullptr));

        auto flush_to_state = log_buffer_->CreateFlushToState(sequence, log_mask);
        EXPECT_TRUE(log_buffer_->FlushTo(test_writer.get(), *flush_to_state, nullptr));
        return {read_log_messages, flush_to_state->start()};
    }

    struct ReaderThreadParams {
        bool non_block = true;
        unsigned long tail = 0;
        LogMask log_mask = kLogMaskAll;
        pid_t pid = 0;
        log_time start_time = {};
        uint64_t sequence = 1;
        std::chrono::steady_clock::time_point deadline = {};
    };

    class TestReaderThread {
      public:
        TestReaderThread(const ReaderThreadParams& params, LogBufferTest& test) : test_(test) {
            auto lock = std::lock_guard{logd_lock};
            std::unique_ptr<LogWriter> test_writer(new TestWriter(&read_log_messages_, &released_));
            std::unique_ptr<LogReaderThread> log_reader(new LogReaderThread(
                    test_.log_buffer_.get(), &test_.reader_list_, std::move(test_writer),
                    params.non_block, params.tail, params.log_mask, params.pid, params.start_time,
                    params.sequence, params.deadline));
            test_.reader_list_.reader_threads().emplace_back(std::move(log_reader));
        }

        void WaitUntilReleased() {
            while (!released_) {
                usleep(5000);
            }
        }

        std::vector<LogMessage> read_log_messages() const { return read_log_messages_; }

        LogBufferTest& test_;
        std::vector<LogMessage> read_log_messages_;
        bool released_ = false;
    };

    std::vector<LogMessage> ReadLogMessagesNonBlockingThread(const ReaderThreadParams& params) {
        EXPECT_TRUE(params.non_block)
                << "params.non_block must be true for ReadLogMessagesNonBlockingThread()";

        auto reader = TestReaderThread(params, *this);
        reader.WaitUntilReleased();
        auto lock = std::lock_guard{logd_lock};
        EXPECT_EQ(0U, reader_list_.reader_threads().size());

        return reader.read_log_messages();
    }

    void ReleaseAndJoinReaders() {
        {
            auto lock = std::lock_guard{logd_lock};
            for (auto& reader : reader_list_.reader_threads()) {
                reader->Release();
            }
        }

        auto retries = 1s / 5000us;
        while (retries--) {
            usleep(5000);
            auto lock = std::lock_guard{logd_lock};
            if (reader_list_.reader_threads().size() == 0) {
                return;
            }
        }

        FAIL() << "ReleaseAndJoinReaders() timed out with reader threads still running";
    }

    LogReaderList reader_list_;
    LogTags tags_;
    PruneList prune_;
    LogStatistics stats_{false, true};
    std::unique_ptr<LogBuffer> log_buffer_;
};
