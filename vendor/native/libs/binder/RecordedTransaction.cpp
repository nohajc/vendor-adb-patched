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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/scopeguard.h>
#include <android-base/unique_fd.h>
#include <binder/RecordedTransaction.h>
#include <sys/mman.h>
#include <algorithm>

using android::Parcel;
using android::base::borrowed_fd;
using android::base::unique_fd;
using android::binder::debug::RecordedTransaction;

#define PADDING8(s) ((8 - (s) % 8) % 8)

static_assert(PADDING8(0) == 0);
static_assert(PADDING8(1) == 7);
static_assert(PADDING8(7) == 1);
static_assert(PADDING8(8) == 0);

// Transactions are sequentially recorded to a file descriptor.
//
// An individual RecordedTransaction is written with the following format:
//
// WARNING: Though the following format is designed to be stable and
// extensible, it is under active development and should be considered
// unstable until this warning is removed.
//
// A RecordedTransaction is written to a file as a sequence of Chunks.
//
// A Chunk consists of a ChunkDescriptor, Data, Padding, and a Checksum.
//
// The ChunkDescriptor identifies the type of Data in the chunk, and the size
// of the Data.
//
// The Data may be any uint32 number of bytes in length in [0-0xfffffff0].
//
// Padding is between [0-7] zero-bytes after the Data such that the Chunk ends
// on an 8-byte boundary. The ChunkDescriptor's dataSize does not include the
// size of Padding.
//
// The checksum is a 64-bit wide XOR of all previous data from the start of the
// ChunkDescriptor to the end of Padding.
//
// ┌───────────────────────────┐
// │Chunk                      │
// │┌────────────────────────┐ │
// ││ChunkDescriptor         │ │
// ││┌───────────┬──────────┐│ │
// │││chunkType  │dataSize  ├┼─┼─┐
// │││uint32_t   │uint32_t  ││ │ │
// ││└───────────┴──────────┘│ │ │
// │└────────────────────────┘ │ │
// │┌─────────────────────────┐│ │
// ││Data                     ││ │
// ││bytes * dataSize         │◀─┘
// ││   ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤│
// ││           Padding       ││
// │└───┴─────────────────────┘│
// │┌─────────────────────────┐│
// ││checksum                 ││
// ││uint64_t                 ││
// │└─────────────────────────┘│
// └───────────────────────────┘
//
// A RecordedTransaction is written as a Header Chunk with fields about the
// transaction, a Data Parcel chunk, a Reply Parcel Chunk, and an End Chunk.
// ┌──────────────────────┐
// │     Header Chunk     │
// ├──────────────────────┤
// │  Sent Parcel Chunk   │
// ├──────────────────────┤
// │  Reply Parcel Chunk  │
// ├──────────────────────┤
// ║      End Chunk       ║
// ╚══════════════════════╝
//
// On reading a RecordedTransaction, an unrecognized chunk is checksummed
// then skipped according to size information in the ChunkDescriptor. Chunks
// are read and either assimilated or skipped until an End Chunk is
// encountered. This has three notable implications:
//
// 1. Older and newer implementations should be able to read one another's
//    Transactions, though there will be loss of information.
// 2. With the exception of the End Chunk, Chunks can appear in any order
//    and even repeat, though this is not recommended.
// 3. If any Chunk is repeated, old values will be overwritten by versions
//    encountered later in the file.
//
// No effort is made to ensure the expected chunks are present. A single
// End Chunk may therefore produce an empty, meaningless RecordedTransaction.

RecordedTransaction::RecordedTransaction(RecordedTransaction&& t) noexcept {
    mData = t.mData;
    mSent.setData(t.getDataParcel().data(), t.getDataParcel().dataSize());
    mReply.setData(t.getReplyParcel().data(), t.getReplyParcel().dataSize());
}

std::optional<RecordedTransaction> RecordedTransaction::fromDetails(
        const String16& interfaceName, uint32_t code, uint32_t flags, timespec timestamp,
        const Parcel& dataParcel, const Parcel& replyParcel, status_t err) {
    RecordedTransaction t;
    t.mData.mHeader = {code,
                       flags,
                       static_cast<int32_t>(err),
                       dataParcel.isForRpc() ? static_cast<uint32_t>(1) : static_cast<uint32_t>(0),
                       static_cast<int64_t>(timestamp.tv_sec),
                       static_cast<int32_t>(timestamp.tv_nsec),
                       0};

    t.mData.mInterfaceName = std::string(String8(interfaceName).string());
    if (interfaceName.size() != t.mData.mInterfaceName.size()) {
        LOG(ERROR) << "Interface Name is not valid. Contains characters that aren't single byte "
                      "utf-8.";
        return std::nullopt;
    }

    if (t.mSent.setData(dataParcel.data(), dataParcel.dataBufferSize()) != android::NO_ERROR) {
        LOG(ERROR) << "Failed to set sent parcel data.";
        return std::nullopt;
    }

    if (t.mReply.setData(replyParcel.data(), replyParcel.dataBufferSize()) != android::NO_ERROR) {
        LOG(ERROR) << "Failed to set reply parcel data.";
        return std::nullopt;
    }

    return std::optional<RecordedTransaction>(std::move(t));
}

enum {
    HEADER_CHUNK = 1,
    DATA_PARCEL_CHUNK = 2,
    REPLY_PARCEL_CHUNK = 3,
    INTERFACE_NAME_CHUNK = 4,
    END_CHUNK = 0x00ffffff,
};

struct ChunkDescriptor {
    uint32_t chunkType = 0;
    uint32_t dataSize = 0;
};
static_assert(sizeof(ChunkDescriptor) % 8 == 0);

constexpr uint32_t kMaxChunkDataSize = 0xfffffff0;
typedef uint64_t transaction_checksum_t;

std::optional<RecordedTransaction> RecordedTransaction::fromFile(const unique_fd& fd) {
    RecordedTransaction t;
    ChunkDescriptor chunk;
    const long pageSize = sysconf(_SC_PAGE_SIZE);
    struct stat fileStat;
    if (fstat(fd.get(), &fileStat) != 0) {
        LOG(ERROR) << "Unable to get file information";
        return std::nullopt;
    }

    off_t fdCurrentPosition = lseek(fd.get(), 0, SEEK_CUR);
    if (fdCurrentPosition == -1) {
        LOG(ERROR) << "Invalid offset in file descriptor.";
        return std::nullopt;
    }
    do {
        if (fileStat.st_size < (fdCurrentPosition + (off_t)sizeof(ChunkDescriptor))) {
            LOG(ERROR) << "Not enough file remains to contain expected chunk descriptor";
            return std::nullopt;
        }

        if (!android::base::ReadFully(fd, &chunk, sizeof(ChunkDescriptor))) {
            LOG(ERROR) << "Failed to read ChunkDescriptor from fd " << fd.get() << ". "
                       << strerror(errno);
            return std::nullopt;
        }
        transaction_checksum_t checksum = *reinterpret_cast<transaction_checksum_t*>(&chunk);

        fdCurrentPosition = lseek(fd.get(), 0, SEEK_CUR);
        if (fdCurrentPosition == -1) {
            LOG(ERROR) << "Invalid offset in file descriptor.";
            return std::nullopt;
        }
        off_t mmapPageAlignedStart = (fdCurrentPosition / pageSize) * pageSize;
        off_t mmapPayloadStartOffset = fdCurrentPosition - mmapPageAlignedStart;

        if (chunk.dataSize > kMaxChunkDataSize) {
            LOG(ERROR) << "Chunk data exceeds maximum size.";
            return std::nullopt;
        }

        size_t chunkPayloadSize =
                chunk.dataSize + PADDING8(chunk.dataSize) + sizeof(transaction_checksum_t);

        if (chunkPayloadSize > (size_t)(fileStat.st_size - fdCurrentPosition)) {
            LOG(ERROR) << "Chunk payload exceeds remaining file size.";
            return std::nullopt;
        }

        if (PADDING8(chunkPayloadSize) != 0) {
            LOG(ERROR) << "Invalid chunk size, not aligned " << chunkPayloadSize;
            return std::nullopt;
        }

        size_t memoryMappedSize = chunkPayloadSize + mmapPayloadStartOffset;
        void* mappedMemory =
                mmap(NULL, memoryMappedSize, PROT_READ, MAP_SHARED, fd.get(), mmapPageAlignedStart);
        auto mmap_guard = android::base::make_scope_guard(
                [mappedMemory, memoryMappedSize] { munmap(mappedMemory, memoryMappedSize); });

        transaction_checksum_t* payloadMap =
                reinterpret_cast<transaction_checksum_t*>(mappedMemory);
        payloadMap += mmapPayloadStartOffset /
                sizeof(transaction_checksum_t); // Skip chunk descriptor and required mmap
                                                // page-alignment
        if (payloadMap == MAP_FAILED) {
            LOG(ERROR) << "Memory mapping failed for fd " << fd.get() << ": " << errno << " "
                       << strerror(errno);
            return std::nullopt;
        }
        for (size_t checksumIndex = 0;
             checksumIndex < chunkPayloadSize / sizeof(transaction_checksum_t); checksumIndex++) {
            checksum ^= payloadMap[checksumIndex];
        }
        if (checksum != 0) {
            LOG(ERROR) << "Checksum failed.";
            return std::nullopt;
        }

        fdCurrentPosition = lseek(fd.get(), chunkPayloadSize, SEEK_CUR);
        if (fdCurrentPosition == -1) {
            LOG(ERROR) << "Invalid offset in file descriptor.";
            return std::nullopt;
        }

        switch (chunk.chunkType) {
            case HEADER_CHUNK: {
                if (chunk.dataSize != static_cast<uint32_t>(sizeof(TransactionHeader))) {
                    LOG(ERROR) << "Header Chunk indicated size " << chunk.dataSize << "; Expected "
                               << sizeof(TransactionHeader) << ".";
                    return std::nullopt;
                }
                t.mData.mHeader = *reinterpret_cast<TransactionHeader*>(payloadMap);
                break;
            }
            case INTERFACE_NAME_CHUNK: {
                t.mData.mInterfaceName =
                        std::string(reinterpret_cast<char*>(payloadMap), chunk.dataSize);
                break;
            }
            case DATA_PARCEL_CHUNK: {
                if (t.mSent.setData(reinterpret_cast<const unsigned char*>(payloadMap),
                                    chunk.dataSize) != android::NO_ERROR) {
                    LOG(ERROR) << "Failed to set sent parcel data.";
                    return std::nullopt;
                }
                break;
            }
            case REPLY_PARCEL_CHUNK: {
                if (t.mReply.setData(reinterpret_cast<const unsigned char*>(payloadMap),
                                     chunk.dataSize) != android::NO_ERROR) {
                    LOG(ERROR) << "Failed to set reply parcel data.";
                    return std::nullopt;
                }
                break;
            }
            case END_CHUNK:
                break;
            default:
                LOG(INFO) << "Unrecognized chunk.";
                break;
        }
    } while (chunk.chunkType != END_CHUNK);

    return std::optional<RecordedTransaction>(std::move(t));
}

android::status_t RecordedTransaction::writeChunk(borrowed_fd fd, uint32_t chunkType,
                                                  size_t byteCount, const uint8_t* data) const {
    if (byteCount > kMaxChunkDataSize) {
        LOG(ERROR) << "Chunk data exceeds maximum size";
        return BAD_VALUE;
    }
    ChunkDescriptor descriptor = {.chunkType = chunkType,
                                  .dataSize = static_cast<uint32_t>(byteCount)};
    // Prepare Chunk content as byte *
    const std::byte* descriptorBytes = reinterpret_cast<const std::byte*>(&descriptor);
    const std::byte* dataBytes = reinterpret_cast<const std::byte*>(data);

    // Add Chunk to intermediate buffer, except checksum
    std::vector<std::byte> buffer;
    buffer.insert(buffer.end(), descriptorBytes, descriptorBytes + sizeof(ChunkDescriptor));
    buffer.insert(buffer.end(), dataBytes, dataBytes + byteCount);
    std::byte zero{0};
    buffer.insert(buffer.end(), PADDING8(byteCount), zero);

    // Calculate checksum from buffer
    transaction_checksum_t* checksumData = reinterpret_cast<transaction_checksum_t*>(buffer.data());
    transaction_checksum_t checksumValue = 0;
    for (size_t idx = 0; idx < (buffer.size() / sizeof(transaction_checksum_t)); idx++) {
        checksumValue ^= checksumData[idx];
    }

    // Write checksum to buffer
    std::byte* checksumBytes = reinterpret_cast<std::byte*>(&checksumValue);
    buffer.insert(buffer.end(), checksumBytes, checksumBytes + sizeof(transaction_checksum_t));

    // Write buffer to file
    if (!android::base::WriteFully(fd, buffer.data(), buffer.size())) {
        LOG(ERROR) << "Failed to write chunk fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    return NO_ERROR;
}

android::status_t RecordedTransaction::dumpToFile(const unique_fd& fd) const {
    if (NO_ERROR !=
        writeChunk(fd, HEADER_CHUNK, sizeof(TransactionHeader),
                   reinterpret_cast<const uint8_t*>(&(mData.mHeader)))) {
        LOG(ERROR) << "Failed to write transactionHeader to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (NO_ERROR !=
        writeChunk(fd, INTERFACE_NAME_CHUNK, mData.mInterfaceName.size() * sizeof(uint8_t),
                   reinterpret_cast<const uint8_t*>(mData.mInterfaceName.c_str()))) {
        LOG(INFO) << "Failed to write Interface Name Chunk to fd " << fd.get();
        return UNKNOWN_ERROR;
    }

    if (NO_ERROR != writeChunk(fd, DATA_PARCEL_CHUNK, mSent.dataBufferSize(), mSent.data())) {
        LOG(ERROR) << "Failed to write sent Parcel to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (NO_ERROR != writeChunk(fd, REPLY_PARCEL_CHUNK, mReply.dataBufferSize(), mReply.data())) {
        LOG(ERROR) << "Failed to write reply Parcel to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (NO_ERROR != writeChunk(fd, END_CHUNK, 0, NULL)) {
        LOG(ERROR) << "Failed to write end chunk to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    return NO_ERROR;
}

const std::string& RecordedTransaction::getInterfaceName() const {
    return mData.mInterfaceName;
}

uint32_t RecordedTransaction::getCode() const {
    return mData.mHeader.code;
}

uint32_t RecordedTransaction::getFlags() const {
    return mData.mHeader.flags;
}

int32_t RecordedTransaction::getReturnedStatus() const {
    return mData.mHeader.statusReturned;
}

timespec RecordedTransaction::getTimestamp() const {
    time_t sec = mData.mHeader.timestampSeconds;
    int32_t nsec = mData.mHeader.timestampNanoseconds;
    return (timespec){.tv_sec = sec, .tv_nsec = nsec};
}

uint32_t RecordedTransaction::getVersion() const {
    return mData.mHeader.version;
}

const Parcel& RecordedTransaction::getDataParcel() const {
    return mSent;
}

const Parcel& RecordedTransaction::getReplyParcel() const {
    return mReply;
}
