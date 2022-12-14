/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <unistd.h>

#include <array>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "incfs_ndk.h"

namespace android::incfs {

using ByteBuffer = std::vector<char>;

enum MountFlags {
    createOnly = INCFS_MOUNT_CREATE_ONLY,
    truncate = INCFS_MOUNT_TRUNCATE,
};

enum Features {
    none = INCFS_FEATURE_NONE,
    core = INCFS_FEATURE_CORE,
    v2 = INCFS_FEATURE_V2,
    mappingFilesProgressFixed = INCFS_FEATURE_MAPPING_FILES_PROGRESS_FIXED,
};

enum class HashAlgorithm {
    none = INCFS_HASH_NONE,
    sha256 = INCFS_HASH_SHA256,
};

enum class CompressionKind {
    none = INCFS_COMPRESSION_KIND_NONE,
    lz4 = INCFS_COMPRESSION_KIND_LZ4,
    zstd = INCFS_COMPRESSION_KIND_ZSTD,
};

enum class BlockKind {
    data = INCFS_BLOCK_KIND_DATA,
    hash = INCFS_BLOCK_KIND_HASH,
};

class UniqueFd {
public:
    explicit UniqueFd(int fd) : fd_(fd) {}
    UniqueFd() : UniqueFd(-1) {}
    ~UniqueFd() { close(); }
    UniqueFd(UniqueFd&& other) noexcept : fd_(other.release()) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        close();
        fd_ = other.release();
        return *this;
    }

    void close() {
        if (ok()) {
            ::close(fd_);
            fd_ = -1;
        }
    }
    int get() const { return fd_; }
    [[nodiscard]] bool ok() const { return fd_ >= 0; }
    [[nodiscard]] int release() { return std::exchange(fd_, -1); }

private:
    int fd_;
};

class UniqueControl {
public:
    UniqueControl(IncFsControl* control = nullptr) : mControl(control) {}
    ~UniqueControl() { close(); }
    UniqueControl(UniqueControl&& other) noexcept
          : mControl(std::exchange(other.mControl, nullptr)) {}
    UniqueControl& operator=(UniqueControl&& other) noexcept {
        close();
        mControl = std::exchange(other.mControl, nullptr);
        return *this;
    }

    IncFsFd cmd() const;
    IncFsFd pendingReads() const;
    IncFsFd logs() const;
    IncFsFd blocksWritten() const;

    void close();

    operator IncFsControl*() const { return mControl; }

    using Fds = std::array<UniqueFd, IncFsFdType::FDS_COUNT>;
    [[nodiscard]] Fds releaseFds();

private:
    IncFsControl* mControl;
};

// A mini version of std::span
template <class T>
class Span {
public:
    using iterator = T*;
    using const_iterator = const T*;

    constexpr Span(T* array, size_t length) : ptr_(array), len_(length) {}
    template <typename V>
    constexpr Span(const std::vector<V>& x) : Span(x.data(), x.size()) {}
    template <typename V, size_t Size>
    constexpr Span(V (&x)[Size]) : Span(x, Size) {}

    constexpr T* data() const { return ptr_; }
    constexpr size_t size() const { return len_; }
    constexpr T& operator[](size_t i) const { return *(data() + i); }
    constexpr iterator begin() const { return data(); }
    constexpr const_iterator cbegin() const { return begin(); }
    constexpr iterator end() const { return data() + size(); }
    constexpr const_iterator cend() const { return end(); }

private:
    T* ptr_;
    size_t len_;
};

struct BlockRange final : public IncFsBlockRange {
    constexpr size_t size() const { return end - begin; }
    constexpr bool empty() const { return end == begin; }
};

class FilledRanges final {
public:
    using RangeBuffer = std::vector<BlockRange>;

    FilledRanges() = default;
    FilledRanges(RangeBuffer&& buffer, IncFsFilledRanges ranges)
          : buffer_(std::move(buffer)), rawFilledRanges_(ranges) {}

    constexpr Span<BlockRange> dataRanges() const {
        return {(BlockRange*)rawFilledRanges_.dataRanges, (size_t)rawFilledRanges_.dataRangesCount};
    }
    constexpr Span<BlockRange> hashRanges() const {
        return {(BlockRange*)rawFilledRanges_.hashRanges, (size_t)rawFilledRanges_.hashRangesCount};
    }

    constexpr size_t totalSize() const { return dataRanges().size() + hashRanges().size(); }

    RangeBuffer extractInternalBufferAndClear() {
        rawFilledRanges_ = {};
        return std::move(buffer_);
    }

    constexpr const RangeBuffer& internalBuffer() const { return buffer_; }
    constexpr IncFsFilledRanges internalRawRanges() const { return rawFilledRanges_; }

private:
    RangeBuffer buffer_;
    IncFsFilledRanges rawFilledRanges_;
};

using Control = UniqueControl;

using FileId = IncFsFileId;
using Size = IncFsSize;
using BlockIndex = IncFsBlockIndex;
using ErrorCode = IncFsErrorCode;
using Fd = IncFsFd;
using Uid = IncFsUid;
using ReadInfo = IncFsReadInfo;
using ReadInfoWithUid = IncFsReadInfoWithUid;
using RawMetadata = ByteBuffer;
using RawSignature = ByteBuffer;
using MountOptions = IncFsMountOptions;
using DataBlock = IncFsDataBlock;
using NewFileParams = IncFsNewFileParams;
using NewMappedFileParams = IncFsNewMappedFileParams;
using BlockCounts = IncFsBlockCounts;
using UidReadTimeouts = IncFsUidReadTimeouts;
using Metrics = IncFsMetrics;
using LastReadError = IncFsLastReadError;

constexpr auto kDefaultReadTimeout = std::chrono::milliseconds(INCFS_DEFAULT_READ_TIMEOUT_MS);
constexpr int kBlockSize = INCFS_DATA_FILE_BLOCK_SIZE;
const auto kInvalidFileId = kIncFsInvalidFileId;
const auto kNoUid = kIncFsNoUid;

bool enabled();
Features features();
bool isValidFileId(FileId fileId);
std::string toString(FileId fileId);
IncFsFileId toFileId(std::string_view str);
bool isIncFsFd(int fd);
bool isIncFsPath(std::string_view path);

UniqueControl mount(std::string_view backingPath, std::string_view targetDir,
                    IncFsMountOptions options);
UniqueControl open(std::string_view dir);
UniqueControl createControl(IncFsFd cmd, IncFsFd pendingReads, IncFsFd logs, IncFsFd blocksWritten);

ErrorCode setOptions(const Control& control, MountOptions newOptions);

ErrorCode bindMount(std::string_view sourceDir, std::string_view targetDir);
ErrorCode unmount(std::string_view dir);

std::string root(const Control& control);

ErrorCode makeFile(const Control& control, std::string_view path, int mode, FileId fileId,
                   NewFileParams params);
ErrorCode makeMappedFile(const Control& control, std::string_view path, int mode,
                         NewMappedFileParams params);
ErrorCode makeDir(const Control& control, std::string_view path, int mode = 0555);
ErrorCode makeDirs(const Control& control, std::string_view path, int mode = 0555);

RawMetadata getMetadata(const Control& control, FileId fileId);
RawMetadata getMetadata(const Control& control, std::string_view path);
FileId getFileId(const Control& control, std::string_view path);

RawSignature getSignature(const Control& control, FileId fileId);
RawSignature getSignature(const Control& control, std::string_view path);

ErrorCode link(const Control& control, std::string_view sourcePath, std::string_view targetPath);
ErrorCode unlink(const Control& control, std::string_view path);

enum class WaitResult { HaveData, Timeout, Error };

WaitResult waitForPendingReads(const Control& control, std::chrono::milliseconds timeout,
                               std::vector<ReadInfo>* pendingReadsBuffer);
WaitResult waitForPageReads(const Control& control, std::chrono::milliseconds timeout,
                            std::vector<ReadInfo>* pageReadsBuffer);
WaitResult waitForPendingReads(const Control& control, std::chrono::milliseconds timeout,
                               std::vector<ReadInfoWithUid>* pendingReadsBuffer);
WaitResult waitForPageReads(const Control& control, std::chrono::milliseconds timeout,
                            std::vector<ReadInfoWithUid>* pageReadsBuffer);

UniqueFd openForSpecialOps(const Control& control, FileId fileId);
UniqueFd openForSpecialOps(const Control& control, std::string_view path);
ErrorCode writeBlocks(Span<const DataBlock> blocks);

std::pair<ErrorCode, FilledRanges> getFilledRanges(int fd);
std::pair<ErrorCode, FilledRanges> getFilledRanges(int fd, FilledRanges::RangeBuffer&& buffer);
std::pair<ErrorCode, FilledRanges> getFilledRanges(int fd, FilledRanges&& resumeFrom);

ErrorCode setUidReadTimeouts(const Control& control, Span<const UidReadTimeouts> timeouts);
std::optional<std::vector<UidReadTimeouts>> getUidReadTimeouts(const Control& control);

std::optional<BlockCounts> getBlockCount(const Control& control, FileId fileId);
std::optional<BlockCounts> getBlockCount(const Control& control, std::string_view path);

std::optional<std::vector<FileId>> listIncompleteFiles(const Control& control);

template <class Callback>
ErrorCode forEachFile(const Control& control, Callback&& cb);
template <class Callback>
ErrorCode forEachIncompleteFile(const Control& control, Callback&& cb);

WaitResult waitForLoadingComplete(const Control& control, std::chrono::milliseconds timeout);

enum class LoadingState { Full, MissingBlocks };
LoadingState isFullyLoaded(int fd);
LoadingState isFullyLoaded(const Control& control, std::string_view path);
LoadingState isFullyLoaded(const Control& control, FileId fileId);
LoadingState isEverythingFullyLoaded(const Control& control);

static const auto kTrimReservedSpace = kIncFsTrimReservedSpace;
ErrorCode reserveSpace(const Control& control, std::string_view path, Size size);
ErrorCode reserveSpace(const Control& control, FileId id, Size size);

std::optional<Metrics> getMetrics(std::string_view sysfsName);
std::optional<LastReadError> getLastReadError(const Control& control);

// Some internal secret API as well that's not backed by C API yet.
class MountRegistry;
MountRegistry& defaultMountRegistry();

} // namespace android::incfs

bool operator==(const IncFsFileId& l, const IncFsFileId& r);
inline bool operator!=(const IncFsFileId& l, const IncFsFileId& r) {
    return !(l == r);
}

namespace std {

template <>
struct hash<IncFsFileId> {
    size_t operator()(const IncFsFileId& id) const noexcept {
        return std::hash<std::string_view>()({&id.data[0], sizeof(id)});
    }
};

} // namespace std

#include "incfs_inline.h"
