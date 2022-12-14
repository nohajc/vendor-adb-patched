/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef ANDROID_OS_WORKSOURCE_H
#define ANDROID_OS_WORKSOURCE_H

#include <optional>
#include <binder/Parcelable.h>
#include <utils/RefBase.h>

namespace android::os {

/**
 * WorkSource is a structure to describes the source of some work that may be done by someone else.
 * This file needs to be kept in sync with frameworks/base/core/java/android/os/WorkSource.java
 */
struct WorkSource : public android::Parcelable {
    WorkSource(
               std::vector<int32_t> uids = {},
               std::optional<std::vector<std::optional<String16>>> names = std::nullopt)
        : mUids(uids),
          mNames(names) {
    }
    std::vector<int32_t> getUids() const { return mUids; }
    std::optional<std::vector<std::optional<String16>>> getNames() const { return mNames; }
    bool operator == (const WorkSource &ws) const {
        return mUids == ws.mUids && mNames == ws.mNames;
    }
    status_t readFromParcel(const android::Parcel* parcel) override;
    status_t writeToParcel(android::Parcel* parcel) const override;

private:
    /** WorkSource UID array */
    std::vector<int32_t> mUids = {};
    /** WorkSource Tag array */
    std::optional<std::vector<std::optional<String16>>> mNames = {};
};

} // namespace android::os

#endif /* ANDROID_OS_WORKSOURCE_H */
