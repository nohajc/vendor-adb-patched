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

#ifndef ANDROID_INCREMENTAL_FILE_SYSTEM_NDK_H
#define ANDROID_INCREMENTAL_FILE_SYSTEM_NDK_H

#include <linux/incrementalfs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

#define INCFS_LIBRARY_NAME "libincfs.so"

typedef struct {
    union {
        char data[16];
        int64_t for_alignment;
    };
} IncFsFileId;

static const IncFsFileId kIncFsInvalidFileId = {
        {{(char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1,
          (char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1}}};

static const int kIncFsFileIdStringLength = sizeof(IncFsFileId) * 2;

typedef enum {
    INCFS_FEATURE_NONE = 0,
    INCFS_FEATURE_CORE = 1 << 0,
    INCFS_FEATURE_V2 = 1 << 1,
    INCFS_FEATURE_MAPPING_FILES_PROGRESS_FIXED = 1 << 2,

} IncFsFeatures;

typedef int IncFsErrorCode;
typedef int64_t IncFsSize;
typedef int32_t IncFsBlockIndex;
typedef int IncFsFd;
typedef struct IncFsControl IncFsControl;
typedef int IncFsUid;

static const IncFsUid kIncFsNoUid = -1;

typedef struct {
    const char* data;
    IncFsSize size;
} IncFsSpan;

typedef enum {
    CMD,
    PENDING_READS,
    LOGS,
    BLOCKS_WRITTEN,
    FDS_COUNT,
} IncFsFdType;

typedef enum {
    INCFS_DEFAULT_READ_TIMEOUT_MS = 10000,
    INCFS_DEFAULT_PENDING_READ_BUFFER_SIZE = 24,
    INCFS_DEFAULT_PAGE_READ_BUFFER_PAGES = 4,
} IncFsDefaults;

typedef enum {
    INCFS_MOUNT_CREATE_ONLY = 1,
    INCFS_MOUNT_TRUNCATE = 2,
} IncFsMountFlags;

typedef enum {
    INCFS_HASH_NONE,
    INCFS_HASH_SHA256,
} IncFsHashAlgortithm;

typedef struct {
    IncFsMountFlags flags;
    int32_t defaultReadTimeoutMs;
    int32_t readLogBufferPages;
    int32_t readLogDisableAfterTimeoutMs;
    const char* sysfsName;
} IncFsMountOptions;

typedef enum {
    INCFS_COMPRESSION_KIND_NONE,
    INCFS_COMPRESSION_KIND_LZ4,
    INCFS_COMPRESSION_KIND_ZSTD,
} IncFsCompressionKind;

typedef enum {
    INCFS_BLOCK_KIND_DATA,
    INCFS_BLOCK_KIND_HASH,
} IncFsBlockKind;

typedef struct {
    IncFsFd fileFd;
    IncFsBlockIndex pageIndex;
    IncFsCompressionKind compression;
    IncFsBlockKind kind;
    uint32_t dataSize;
    const char* data;
} IncFsDataBlock;

typedef struct {
    IncFsSize size;
    IncFsSpan metadata;
    IncFsSpan signature;
} IncFsNewFileParams;

typedef struct {
    IncFsFileId sourceId;
    IncFsSize sourceOffset;
    IncFsSize size;
} IncFsNewMappedFileParams;

typedef struct {
    IncFsFileId id;
    uint64_t bootClockTsUs;
    IncFsBlockIndex block;
    uint32_t serialNo;
} IncFsReadInfo;

typedef struct {
    IncFsFileId id;
    uint64_t bootClockTsUs;
    IncFsBlockIndex block;
    uint32_t serialNo;
    IncFsUid uid;
} IncFsReadInfoWithUid;

typedef struct {
    IncFsBlockIndex begin;
    IncFsBlockIndex end;
} IncFsBlockRange;

typedef struct {
    IncFsBlockRange* dataRanges;
    IncFsBlockRange* hashRanges;
    int32_t dataRangesCount;
    int32_t hashRangesCount;
    IncFsBlockIndex endIndex;
} IncFsFilledRanges;

typedef struct {
    IncFsSize totalDataBlocks;
    IncFsSize filledDataBlocks;
    IncFsSize totalHashBlocks;
    IncFsSize filledHashBlocks;
} IncFsBlockCounts;

typedef struct {
    IncFsUid uid;
    uint32_t minTimeUs;
    uint32_t minPendingTimeUs;
    uint32_t maxPendingTimeUs;
} IncFsUidReadTimeouts;

typedef struct {
    uint32_t readsDelayedMin;
    uint64_t readsDelayedMinUs;
    uint32_t readsDelayedPending;
    uint64_t readsDelayedPendingUs;
    uint32_t readsFailedHashVerification;
    uint32_t readsFailedOther;
    uint32_t readsFailedTimedOut;
    uint64_t reserved;
    uint64_t reserved1;
} IncFsMetrics;

typedef struct {
    IncFsFileId id;
    uint64_t timestampUs;
    IncFsBlockIndex block;
    uint32_t errorNo;
    IncFsUid uid;
} IncFsLastReadError;

// All functions return -errno in case of failure.
// All IncFsFd functions return >=0 in case of success.
// All IncFsFileId functions return invalid IncFsFileId on error.
// All IncFsErrorCode functions return 0 in case of success.

bool IncFs_IsEnabled();
IncFsFeatures IncFs_Features();

bool IncFs_IsIncFsFd(int fd);
bool IncFs_IsIncFsPath(const char* path);

static inline bool IncFs_IsValidFileId(IncFsFileId fileId) {
    return memcmp(&fileId, &kIncFsInvalidFileId, sizeof(fileId)) != 0;
}

int IncFs_FileIdToString(IncFsFileId id, char* out);
IncFsFileId IncFs_FileIdFromString(const char* in);

IncFsFileId IncFs_FileIdFromMetadata(IncFsSpan metadata);

IncFsControl* IncFs_Mount(const char* backingPath, const char* targetDir,
                          IncFsMountOptions options);
IncFsControl* IncFs_Open(const char* dir);
IncFsControl* IncFs_CreateControl(IncFsFd cmd, IncFsFd pendingReads, IncFsFd logs,
                                  IncFsFd blocksWritten);
void IncFs_DeleteControl(IncFsControl* control);
IncFsFd IncFs_GetControlFd(const IncFsControl* control, IncFsFdType type);
IncFsSize IncFs_ReleaseControlFds(IncFsControl* control, IncFsFd out[], IncFsSize outSize);

IncFsErrorCode IncFs_SetOptions(const IncFsControl* control, IncFsMountOptions options);

IncFsErrorCode IncFs_BindMount(const char* sourceDir, const char* targetDir);
IncFsErrorCode IncFs_Unmount(const char* dir);

IncFsErrorCode IncFs_Root(const IncFsControl* control, char buffer[], size_t* bufferSize);

IncFsErrorCode IncFs_MakeFile(const IncFsControl* control, const char* path, int32_t mode,
                              IncFsFileId id, IncFsNewFileParams params);
IncFsErrorCode IncFs_MakeMappedFile(const IncFsControl* control, const char* path, int32_t mode,
                                    IncFsNewMappedFileParams params);

IncFsErrorCode IncFs_MakeDir(const IncFsControl* control, const char* path, int32_t mode);
IncFsErrorCode IncFs_MakeDirs(const IncFsControl* control, const char* path, int32_t mode);

IncFsErrorCode IncFs_GetMetadataById(const IncFsControl* control, IncFsFileId id, char buffer[],
                                     size_t* bufferSize);
IncFsErrorCode IncFs_GetMetadataByPath(const IncFsControl* control, const char* path, char buffer[],
                                       size_t* bufferSize);

IncFsErrorCode IncFs_GetSignatureById(const IncFsControl* control, IncFsFileId id, char buffer[],
                                      size_t* bufferSize);
IncFsErrorCode IncFs_GetSignatureByPath(const IncFsControl* control, const char* path,
                                        char buffer[], size_t* bufferSize);
IncFsErrorCode IncFs_UnsafeGetSignatureByPath(const char* path, char buffer[], size_t* bufferSize);

IncFsFileId IncFs_GetId(const IncFsControl* control, const char* path);

IncFsErrorCode IncFs_Link(const IncFsControl* control, const char* sourcePath,
                          const char* targetPath);
IncFsErrorCode IncFs_Unlink(const IncFsControl* control, const char* path);

IncFsErrorCode IncFs_WaitForPendingReads(const IncFsControl* control, int32_t timeoutMs,
                                         IncFsReadInfo buffer[], size_t* bufferSize);
IncFsErrorCode IncFs_WaitForPageReads(const IncFsControl* control, int32_t timeoutMs,
                                      IncFsReadInfo buffer[], size_t* bufferSize);

IncFsErrorCode IncFs_WaitForPendingReadsWithUid(const IncFsControl* control, int32_t timeoutMs,
                                                IncFsReadInfoWithUid buffer[], size_t* bufferSize);
IncFsErrorCode IncFs_WaitForPageReadsWithUid(const IncFsControl* control, int32_t timeoutMs,
                                             IncFsReadInfoWithUid buffer[], size_t* bufferSize);

IncFsErrorCode IncFs_WaitForFsWrittenBlocksChange(const IncFsControl* control, int32_t timeoutMs,
                                                  IncFsSize* count);

IncFsFd IncFs_OpenForSpecialOpsByPath(const IncFsControl* control, const char* path);
IncFsFd IncFs_OpenForSpecialOpsById(const IncFsControl* control, IncFsFileId id);

IncFsErrorCode IncFs_WriteBlocks(const IncFsDataBlock blocks[], size_t blocksCount);

IncFsErrorCode IncFs_SetUidReadTimeouts(const IncFsControl* control,
                                        const IncFsUidReadTimeouts timeouts[], size_t count);
IncFsErrorCode IncFs_GetUidReadTimeouts(const IncFsControl* control,
                                        IncFsUidReadTimeouts timeoutsBuffer[], size_t* bufferSize);

IncFsErrorCode IncFs_GetFileBlockCountByPath(const IncFsControl* control, const char* path,
                                             IncFsBlockCounts* blockCount);
IncFsErrorCode IncFs_GetFileBlockCountById(const IncFsControl* control, IncFsFileId id,
                                           IncFsBlockCounts* blockCount);

IncFsErrorCode IncFs_ListIncompleteFiles(const IncFsControl* control, IncFsFileId ids[],
                                         size_t* bufferSize);

// Calls a passed callback for each file on the mounted filesystem, or, in the second case,
// for each incomplete file (only for v2 IncFS).
// Callback can stop the iteration early by returning |false|.
// Return codes:
// >=0      - number of files iterated,
// <0       - -errno
typedef bool (*FileCallback)(void* context, const IncFsControl* control, IncFsFileId fileId);
IncFsErrorCode IncFs_ForEachFile(const IncFsControl* control, void* context, FileCallback cb);
IncFsErrorCode IncFs_ForEachIncompleteFile(const IncFsControl* control, void* context,
                                           FileCallback cb);

IncFsErrorCode IncFs_WaitForLoadingComplete(const IncFsControl* control, int32_t timeoutMs);

// Gets a collection of filled ranges in the file from IncFS. Uses the |outBuffer| memory, it has
// to be big enough to fit all the ranges the caller is expecting.
// Return codes:
//  0       - success,
//  -ERANGE - input buffer is too small. filledRanges are still valid up to the outBuffer.size,
//            but there are more,
//  <0      - error, |filledRanges| is not valid.
IncFsErrorCode IncFs_GetFilledRanges(int fd, IncFsSpan outBuffer, IncFsFilledRanges* filledRanges);
IncFsErrorCode IncFs_GetFilledRangesStartingFrom(int fd, int startBlockIndex, IncFsSpan outBuffer,
                                                 IncFsFilledRanges* filledRanges);
// Check if the file is fully loaded. Return codes:
//  0        - fully loaded,
//  -ENODATA - some blocks are missing,
//  <0       - error from the syscall.
IncFsErrorCode IncFs_IsFullyLoaded(int fd);
IncFsErrorCode IncFs_IsFullyLoadedByPath(const IncFsControl* control, const char* path);
IncFsErrorCode IncFs_IsFullyLoadedById(const IncFsControl* control, IncFsFileId fileId);

// Check if all files on the mount are fully loaded. Return codes:
//  0        - fully loaded,
//  -ENODATA - some blocks are missing,
//  <0       - error from the syscall.
IncFsErrorCode IncFs_IsEverythingFullyLoaded(const IncFsControl* control);

// Reserve |size| bytes for the file. Trims reserved space to the current file size when |size = -1|
static const IncFsSize kIncFsTrimReservedSpace = -1;
IncFsErrorCode IncFs_ReserveSpaceByPath(const IncFsControl* control, const char* path,
                                        IncFsSize size);
IncFsErrorCode IncFs_ReserveSpaceById(const IncFsControl* control, IncFsFileId id, IncFsSize size);

// Gets the metrics of a mount by specifying the corresponding sysfs subpath.
// Return codes:
// =0       - success
// <0       - -errno
IncFsErrorCode IncFs_GetMetrics(const char* sysfsName, IncFsMetrics* metrics);

// Gets information about the last read error of a mount.
// Return codes:
// =0       - success
// <0       - -errno
// When there is no read error, still returns success. Fields in IncFsLastReadError will be all 0.
// Possible values of IncFsLastReadError.errorNo:
//   -ETIME for read timeout;
//   -EBADMSG for hash verification failure;
//   Other negative values for other types of errors.
IncFsErrorCode IncFs_GetLastReadError(const IncFsControl* control,
                                      IncFsLastReadError* lastReadError);

__END_DECLS

#endif // ANDROID_INCREMENTAL_FILE_SYSTEM_NDK_H
