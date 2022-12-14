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

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "dataloader_ndk.h"
#include "incfs.h"

namespace android::dataloader {

using DataLoaderStatus = ::DataLoaderStatus;
template <class T>
using Span = android::incfs::Span<T>;

struct DataLoader;
struct DataLoaderParams;
struct DataLoaderInstallationFile;
struct FilesystemConnector;
struct StatusListener;

using FileId = IncFsFileId;
using ReadInfo = IncFsReadInfo;
using DataBlock = IncFsDataBlock;

using FilesystemConnectorPtr = FilesystemConnector*;
using StatusListenerPtr = StatusListener*;
using ServiceConnectorPtr = DataLoaderServiceConnectorPtr;
using ServiceParamsPtr = DataLoaderServiceParamsPtr;

using DataLoaderPtr = std::unique_ptr<DataLoader>;
using DataLoaderInstallationFiles = Span<const ::DataLoaderInstallationFile>;
using PendingReads = Span<const ReadInfo>;
using PageReads = Span<const ReadInfo>;
using RawMetadata = std::vector<char>;
using DataBlocks = Span<const DataBlock>;

constexpr int kBlockSize = INCFS_DATA_FILE_BLOCK_SIZE;

struct DataLoader {
    using Factory = std::function<DataLoaderPtr(DataLoaderServiceVmPtr, const DataLoaderParams&)>;
    static void initialize(Factory&& factory);

    virtual ~DataLoader() {}

    // Lifecycle.
    virtual bool onCreate(const DataLoaderParams&, FilesystemConnectorPtr, StatusListenerPtr,
                          ServiceConnectorPtr, ServiceParamsPtr) = 0;
    virtual bool onStart() = 0;
    virtual void onStop() = 0;
    virtual void onDestroy() = 0;

    // FS callbacks.
    virtual bool onPrepareImage(DataLoaderInstallationFiles addedFiles) = 0;

    // IFS callbacks.
    virtual void onPendingReads(PendingReads pendingReads) = 0;
    virtual void onPageReads(PageReads pageReads) = 0;
};

struct DataLoaderParams {
    DataLoaderType type() const { return mType; }
    const std::string& packageName() const { return mPackageName; }
    const std::string& className() const { return mClassName; }
    const std::string& arguments() const { return mArguments; }

    DataLoaderParams(DataLoaderType type, std::string&& packageName, std::string&& className,
                     std::string&& arguments);

private:
    DataLoaderType const mType;
    std::string const mPackageName;
    std::string const mClassName;
    std::string const mArguments;
};

struct DataLoaderInstallationFile {
    DataLoaderLocation location() const { return mLocation; }
    const std::string& name() const { return mName; }
    IncFsSize size() const { return mSize; }
    const RawMetadata& metadata() const { return mMetadata; }

    DataLoaderInstallationFile(DataLoaderLocation location, std::string&& name, IncFsSize size,
                               RawMetadata&& metadata);

private:
    DataLoaderLocation const mLocation;
    std::string const mName;
    IncFsSize const mSize;
    RawMetadata const mMetadata;
};

struct FilesystemConnector : public DataLoaderFilesystemConnector {
    android::incfs::UniqueFd openForSpecialOps(FileId fid);
    int writeBlocks(DataBlocks blocks);
    RawMetadata getRawMetadata(FileId fid);
    bool setParams(DataLoaderFilesystemParams);
};

struct StatusListener : public DataLoaderStatusListener {
    bool reportStatus(DataLoaderStatus status);
};

} // namespace android::dataloader

#include "dataloader_inline.h"
