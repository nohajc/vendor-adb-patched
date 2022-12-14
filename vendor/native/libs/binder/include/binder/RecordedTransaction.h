/*
 * Copyright (C) 2022, The Android Open Source Project
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

#pragma once

#include <android-base/unique_fd.h>
#include <binder/Parcel.h>
#include <mutex>

namespace android {

namespace binder::debug {

// Warning: Transactions are sequentially recorded to the file descriptor in a
// non-stable format. A detailed description of the recording format can be found in
// RecordedTransaction.cpp.

class RecordedTransaction {
public:
    // Filled with the first transaction from fd.
    static std::optional<RecordedTransaction> fromFile(const android::base::unique_fd& fd);
    // Filled with the arguments.
    static std::optional<RecordedTransaction> fromDetails(const String16& interfaceName,
                                                          uint32_t code, uint32_t flags,
                                                          timespec timestamp, const Parcel& data,
                                                          const Parcel& reply, status_t err);
    RecordedTransaction(RecordedTransaction&& t) noexcept;

    [[nodiscard]] status_t dumpToFile(const android::base::unique_fd& fd) const;

    const std::string& getInterfaceName() const;
    uint32_t getCode() const;
    uint32_t getFlags() const;
    int32_t getReturnedStatus() const;
    timespec getTimestamp() const;
    uint32_t getVersion() const;
    const Parcel& getDataParcel() const;
    const Parcel& getReplyParcel() const;

private:
    RecordedTransaction() = default;

    android::status_t writeChunk(const android::base::borrowed_fd, uint32_t chunkType,
                                 size_t byteCount, const uint8_t* data) const;

#pragma clang diagnostic push
#pragma clang diagnostic error "-Wpadded"
    struct TransactionHeader {
        uint32_t code = 0;
        uint32_t flags = 0;
        int32_t statusReturned = 0;
        uint32_t version = 0; // !0 iff Rpc
        int64_t timestampSeconds = 0;
        int32_t timestampNanoseconds = 0;
        int32_t reserved = 0;
    };
#pragma clang diagnostic pop
    static_assert(sizeof(TransactionHeader) == 32);
    static_assert(sizeof(TransactionHeader) % 8 == 0);

    struct MovableData { // movable
        TransactionHeader mHeader;
        std::string mInterfaceName;
    };
    MovableData mData;
    Parcel mSent;
    Parcel mReply;
};

} // namespace binder::debug

} // namespace android
