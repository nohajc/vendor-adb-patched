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

#define LOG_TAG "WorkSource"

#include <android/WorkSource.h>
#include <binder/Parcel.h>
#include <utils/Log.h>

namespace android::os {

status_t WorkSource::readFromParcel(const android::Parcel *parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }
    int32_t num;
    int32_t workChainCount;
    status_t ret = parcel->readInt32(&num)
                ?: parcel->readInt32Vector(&mUids)
                ?: parcel->readString16Vector(&mNames)
                ?: parcel->readInt32(&workChainCount);

    if (ret == OK && workChainCount > 0) {
        // We don't yet support WorkChains in native WorkSources.
        return BAD_VALUE;
    }

    return ret;
}

status_t WorkSource::writeToParcel(android::Parcel *parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    return parcel->writeInt32(mUids.size())
        ?: parcel->writeInt32Vector(mUids)
        ?: parcel->writeString16Vector(mNames)
        ?: parcel->writeInt32(-1);
}

} // namespace android::os
