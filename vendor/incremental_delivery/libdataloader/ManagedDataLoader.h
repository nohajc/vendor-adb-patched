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

namespace android::dataloader {

// Default DataLoader redirects everything back to Java.
struct ManagedDataLoader : public DataLoader {
    ManagedDataLoader(JavaVM* jvm);

private:
    // Lifecycle.
    bool onCreate(const android::dataloader::DataLoaderParams&,
                  android::dataloader::FilesystemConnectorPtr ifs,
                  android::dataloader::StatusListenerPtr listener,
                  android::dataloader::ServiceConnectorPtr service,
                  android::dataloader::ServiceParamsPtr params) final;
    bool onStart() final { return true; }
    void onStop() final {}
    void onDestroy() final;

    bool onPrepareImage(DataLoaderInstallationFiles addedFiles) final;

    void onPendingReads(PendingReads pendingReads) final {}
    void onPageReads(PageReads pageReads) final {}

    JavaVM* const mJvm;
    jobject mDataLoader = nullptr;
};

} // namespace android::dataloader
