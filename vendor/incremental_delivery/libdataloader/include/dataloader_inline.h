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

#include "dataloader.h"

namespace android::dataloader {
namespace details {

struct DataLoaderImpl : public ::DataLoader {
    DataLoaderImpl(DataLoaderPtr&& dataLoader) : mDataLoader(std::move(dataLoader)) {
        onStart = [](DataLoader* self) -> bool {
            return static_cast<DataLoaderImpl*>(self)->mDataLoader->onStart();
        };
        onStop = [](DataLoader* self) {
            return static_cast<DataLoaderImpl*>(self)->mDataLoader->onStop();
        };
        onDestroy = [](DataLoader* self) {
            auto me = static_cast<DataLoaderImpl*>(self);
            me->mDataLoader->onDestroy();
            delete me;
        };
        onPrepareImage = [](DataLoader* self, const ::DataLoaderInstallationFile addedFiles[],
                            int addedFilesCount) -> bool {
            return static_cast<DataLoaderImpl*>(self)->mDataLoader->onPrepareImage(
                    DataLoaderInstallationFiles(addedFiles, addedFilesCount));
        };
        onPendingReads = [](DataLoader* self, const IncFsReadInfo pendingReads[],
                            int pendingReadsCount) {
            return static_cast<DataLoaderImpl*>(self)->mDataLoader->onPendingReads(
                    PendingReads(pendingReads, pendingReadsCount));
        };
        onPageReads = [](DataLoader* self, const IncFsReadInfo pageReads[], int pageReadsCount) {
            return static_cast<DataLoaderImpl*>(self)->mDataLoader->onPageReads(
                    PageReads(pageReads, pageReadsCount));
        };
    }

private:
    DataLoaderPtr mDataLoader;
};

inline DataLoaderParams createParams(const ::DataLoaderParams* params) {
    const DataLoaderType type((DataLoaderType)params->type);
    std::string packageName(params->packageName);
    std::string className(params->className);
    std::string arguments(params->arguments);
    return DataLoaderParams(type, std::move(packageName), std::move(className),
                            std::move(arguments));
}

inline DataLoaderInstallationFile createInstallationFile(const ::DataLoaderInstallationFile* file) {
    const DataLoaderLocation location((DataLoaderLocation)file->location);
    std::string name(file->name);
    IncFsSize size(file->size);
    RawMetadata metadata(file->metadata.data, file->metadata.data + file->metadata.size);
    return DataLoaderInstallationFile(location, std::move(name), size, std::move(metadata));
}

struct DataLoaderFactoryImpl : public ::DataLoaderFactory {
    DataLoaderFactoryImpl(DataLoader::Factory&& factory) : mFactory(factory) {
        onCreate = [](::DataLoaderFactory* self, const ::DataLoaderParams* ndkParams,
                      ::DataLoaderFilesystemConnectorPtr fsConnector,
                      ::DataLoaderStatusListenerPtr statusListener, ::DataLoaderServiceVmPtr vm,
                      ::DataLoaderServiceConnectorPtr serviceConnector,
                      ::DataLoaderServiceParamsPtr serviceParams) {
            auto me = static_cast<DataLoaderFactoryImpl*>(self);
            ::DataLoader* result = nullptr;
            auto params = createParams(ndkParams);
            auto dataLoader = me->mFactory(vm, params);
            if (!dataLoader ||
                !dataLoader->onCreate(params, static_cast<FilesystemConnector*>(fsConnector),
                                      static_cast<StatusListener*>(statusListener),
                                      serviceConnector, serviceParams)) {
                return result;
            }
            result = new DataLoaderImpl(std::move(dataLoader));
            return result;
        };
    }

private:
    DataLoader::Factory mFactory;
};

} // namespace details

inline void DataLoader::initialize(DataLoader::Factory&& factory) {
    DataLoader_Initialize(new details::DataLoaderFactoryImpl(std::move(factory)));
}

inline DataLoaderParams::DataLoaderParams(DataLoaderType type, std::string&& packageName,
                                          std::string&& className, std::string&& arguments)
      : mType(type),
        mPackageName(std::move(packageName)),
        mClassName(std::move(className)),
        mArguments(std::move(arguments)) {}

inline DataLoaderInstallationFile::DataLoaderInstallationFile(DataLoaderLocation location,
                                                              std::string&& name, IncFsSize size,
                                                              RawMetadata&& metadata)
      : mLocation(location), mName(std::move(name)), mSize(size), mMetadata(std::move(metadata)) {}

inline android::incfs::UniqueFd FilesystemConnector::openForSpecialOps(FileId fid) {
    return android::incfs::UniqueFd(DataLoader_FilesystemConnector_openForSpecialOps(this, fid));
}

inline int FilesystemConnector::writeBlocks(DataBlocks blocks) {
    return DataLoader_FilesystemConnector_writeBlocks(this, blocks.data(), blocks.size());
}

inline RawMetadata FilesystemConnector::getRawMetadata(FileId fid) {
    RawMetadata metadata(INCFS_MAX_FILE_ATTR_SIZE);
    size_t size = metadata.size();
    if (DataLoader_FilesystemConnector_getRawMetadata(this, fid, metadata.data(), &size) < 0) {
        return {};
    }
    metadata.resize(size);
    return metadata;
}

inline bool FilesystemConnector::setParams(DataLoaderFilesystemParams params) {
    return DataLoader_FilesystemConnector_setParams(this, params);
}

inline bool StatusListener::reportStatus(DataLoaderStatus status) {
    return DataLoader_StatusListener_reportStatus(this, status);
}

} // namespace android::dataloader
