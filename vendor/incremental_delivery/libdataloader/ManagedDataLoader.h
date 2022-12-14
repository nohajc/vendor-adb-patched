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

#include <dataloader.h>

__BEGIN_DECLS

// This simulates legacy dataloader (compiled with previous version of libincfs_dataloader).
// We still need to be able to support them.
struct LegacyDataLoader {
    bool (*onStart)(struct LegacyDataLoader* self);
    void (*onStop)(struct LegacyDataLoader* self);
    void (*onDestroy)(struct LegacyDataLoader* self);

    bool (*onPrepareImage)(struct LegacyDataLoader* self,
                           const DataLoaderInstallationFile addedFiles[], int addedFilesCount);

    void (*onPendingReads)(struct LegacyDataLoader* self, const IncFsReadInfo pendingReads[],
                           int pendingReadsCount);
    void (*onPageReads)(struct LegacyDataLoader* self, const IncFsReadInfo pageReads[],
                        int pageReadsCount);
};

__END_DECLS

namespace android::dataloader {

// Default DataLoader redirects everything back to Java.
struct ManagedDataLoader : private LegacyDataLoader {
    static LegacyDataLoader* create(JavaVM* jvm, android::dataloader::FilesystemConnectorPtr ifs,
                                    android::dataloader::StatusListenerPtr listener,
                                    android::dataloader::ServiceConnectorPtr service,
                                    android::dataloader::ServiceParamsPtr params);

private:
    ManagedDataLoader(JavaVM* jvm, jobject dataLoader);

    // Lifecycle.
    void onDestroy();

    // Installation.
    bool onPrepareImage(DataLoaderInstallationFiles addedFiles);

    JavaVM* const mJvm;
    jobject mDataLoader = nullptr;
};

struct ManagedDataLoaderFactory : public ::DataLoaderFactory {
    ManagedDataLoaderFactory();
};

} // namespace android::dataloader
