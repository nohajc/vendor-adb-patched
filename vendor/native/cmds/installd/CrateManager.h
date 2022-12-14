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

#ifndef ANDROID_INSTALLD_CRATE_INFO_MANAGER_H
#define ANDROID_INSTALLD_CRATE_INFO_MANAGER_H

#ifdef ENABLE_STORAGE_CRATES

#include <android/os/storage/CrateMetadata.h>
#include <cutils/multiuser.h>
#include <fts.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <optional>
#include <string>
#include <vector>

#ifndef CRATE_DEBUG
#define CRATE_DEBUG 1
#endif

namespace android {
namespace installd {

using android::os::storage::CrateMetadata;

/**
 * The crated folder actually is a folder that is the first level child director. In order to
 * distingish between the crated folder and the other FTSENT*, to define the type "CratedFolder"
 * make the code easy to identify the difference.
 */
typedef FTSENT* CratedFolder;

/**
 * In order to give the users more fine-grained files controlling, the crate information can help
 * applications' developers to show the more detail information to the users. The crate information
 * include the Label, Expiration etc..
 */
class CrateManager {
public:
    CrateManager(const char* uuid, userid_t userId, const std::string& packageName);
    ~CrateManager();

    void traverseAllCrates(std::function<void(CratedFolder, CrateMetadata&&)>& onCreateCrate);

    static void traverseChildDir(const std::string& targetDir,
            std::function<void(FTSENT*)>& onVisitChildDir);

    static void traverseAllPackagesForUser(
        const std::optional<std::string>& uuid,
        userid_t userId,
        std::function<void(FTSENT*)>& onHandlingPackage);

#if CRATE_DEBUG
    static void dump(const CrateMetadata& CrateMetadata);
#endif
private:
    std::string mRoot;
    std::string mCratedFoldersRoot;
    std::string mPackageName;

    void createCrate(
        CratedFolder cratedFolder,
        std::function<void(CratedFolder, CrateMetadata&&)>& onCreateCrate);
};

} // namespace installd
} // namespace android

#else // ENABLE_STORAGE_CRATES
#include <android/os/storage/CrateMetadata.h>
using android::os::storage::CrateMetadata;
#endif // ENABLE_STORAGE_CRATES

#endif // ANDROID_INSTALLD_CRATE_INFO_MANAGER_H
