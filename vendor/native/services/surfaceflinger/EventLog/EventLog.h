/*
 * Copyright 2013 The Android Open Source Project
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

#include <utils/Errors.h>
#include <utils/Singleton.h>

#include <cstdint>
#include <string_view>

namespace android {

class EventLog : public Singleton<EventLog> {

public:
    static void logFrameDurations(const std::string_view& name, const int32_t* durations,
                                  size_t numDurations);

protected:
    EventLog();

private:
    /*
     * EventLogBuffer is a helper class to construct an in-memory event log
     * tag. In this version the buffer is not dynamic, so write operation can
     * fail if there is not enough space in the temporary buffer.
     * Once constructed, the buffer can be logger by calling the log()
     * method.
     */

    class TagBuffer {
        enum { STORAGE_MAX_SIZE = 128 };
        int32_t mPos;
        int32_t mTag;
        bool mOverflow;
        char mStorage[STORAGE_MAX_SIZE];
    public:
        explicit TagBuffer(int32_t tag);

        void startList(int8_t count);
        void endList();

        void writeInt32(int32_t);
        void writeInt64(int64_t);
        void writeString(const std::string_view&);

        void log();
    };

    friend class Singleton<EventLog>;
    EventLog(const EventLog&);
    EventLog& operator =(const EventLog&);

    enum { LOGTAG_SF_FRAME_DUR = 60100 };
    void doLogFrameDurations(const std::string_view& name, const int32_t* durations,
                             size_t numDurations);
};

} // namespace android
