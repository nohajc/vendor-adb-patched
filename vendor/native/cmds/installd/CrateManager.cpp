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

#include "CrateManager.h"

#ifdef ENABLE_STORAGE_CRATES

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android/log.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdint.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <fstream>
#include <string>
#include <utils.h>

#include "utils.h"

using android::base::StringPrintf;

namespace android {
namespace installd {

CrateManager::CrateManager(const char* uuid, userid_t userId, const std::string& packageName) {
    mPackageName = packageName;
    mRoot = create_data_user_ce_package_path(uuid, userId, (const char*)packageName.c_str());
    mCratedFoldersRoot = StringPrintf("%s/crates", mRoot.c_str());
}

CrateManager::~CrateManager() {}

static std::string getValidatedCratedPath(std::string path) {
    size_t pos = path.rfind("/");
    if (pos == std::string::npos) {
        return path;
    }

    return path.substr(pos + 1, path.length());
}

void CrateManager::traverseChildDir(const std::string& targetDir,
    std::function<void(FTSENT*)>& onVisitChildDir) {
    char* argv[] = {(char*)targetDir.c_str(), nullptr};
    FTS* fts = fts_open(argv, FTS_PHYSICAL | FTS_NOCHDIR | FTS_XDEV, nullptr);
    if (fts == nullptr) {
        PLOG(WARNING) << "Failed to fts_open " << targetDir;
        return;
    }

    FTSENT* p;
    while ((p = fts_read(fts)) != nullptr) {
        switch (p->fts_info) {
            case FTS_D:
                if (p->fts_level == 1) {
                    onVisitChildDir(p);
                }
                break;
            default:
                break;
        }

        if (p->fts_level == 1) {
            fts_set(fts, p, FTS_SKIP);
        }
    }
    fts_close(fts);
}

void CrateManager::traverseAllPackagesForUser(
        const std::optional<std::string>& uuid, userid_t userId,
        std::function<void(FTSENT*)>& onHandlingPackage) {
    const char* uuid_ = uuid ? uuid->c_str() : nullptr;

    auto ce_path = create_data_user_ce_path(uuid_, userId);
    traverseChildDir(ce_path, onHandlingPackage);
}

void CrateManager::createCrate(
        CratedFolder cratedFolder,
        std::function<void(CratedFolder, CrateMetadata&&)>& onCreateCrate) {
    const char* path = cratedFolder->fts_path;
    if (path == nullptr || *path == '\0') {
        return;
    }

    CrateMetadata crateMetadata;
    crateMetadata.uid = cratedFolder->fts_statp->st_uid;
    crateMetadata.packageName = mPackageName;
    crateMetadata.id = getValidatedCratedPath(path);

    onCreateCrate(cratedFolder, std::move(crateMetadata));
}

void CrateManager::traverseAllCrates(std::function<void(CratedFolder, CrateMetadata&&)>& onCreateCrate) {
    std::function<void(FTSENT*)> onVisitCrateDir = [&](FTSENT* cratedFolder) -> void {
        createCrate(cratedFolder, onCreateCrate);
    };
    traverseChildDir(mCratedFoldersRoot, onVisitCrateDir);
}

#if CRATE_DEBUG
void CrateManager::dump(const CrateMetadata& CrateMetadata) {
    LOG(DEBUG) << "CrateMetadata = {"
            << "uid : \"" << CrateMetadata.uid
            << "\", packageName : \"" << CrateMetadata.packageName
            << "\", id : \"" << CrateMetadata.id
            << "\"}";
}
#endif

} // namespace installd
} // namespace android

#endif // ENABLE_STORAGE_CRATES