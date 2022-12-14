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

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <binder/ParcelableHolder.h>

#define RETURN_ON_FAILURE(expr)                     \
    do {                                            \
        android::status_t _status = (expr);         \
        if (_status != android::OK) return _status; \
    } while (false)

namespace android {
namespace os {
status_t ParcelableHolder::writeToParcel(Parcel* p) const {
    RETURN_ON_FAILURE(p->writeInt32(static_cast<int32_t>(this->getStability())));
    if (this->mParcelPtr) {
        RETURN_ON_FAILURE(p->writeInt32(this->mParcelPtr->dataSize()));
        RETURN_ON_FAILURE(p->appendFrom(this->mParcelPtr.get(), 0, this->mParcelPtr->dataSize()));
        return OK;
    }
    if (this->mParcelable) {
        size_t sizePos = p->dataPosition();
        RETURN_ON_FAILURE(p->writeInt32(0));
        size_t dataStartPos = p->dataPosition();
        RETURN_ON_FAILURE(p->writeString16(this->mParcelableName));
        this->mParcelable->writeToParcel(p);
        size_t dataSize = p->dataPosition() - dataStartPos;

        p->setDataPosition(sizePos);
        RETURN_ON_FAILURE(p->writeInt32(dataSize));
        p->setDataPosition(p->dataPosition() + dataSize);
        return OK;
    }

    RETURN_ON_FAILURE(p->writeInt32(0));
    return OK;
}

status_t ParcelableHolder::readFromParcel(const Parcel* p) {
    this->mStability = static_cast<Stability>(p->readInt32());
    this->mParcelable = nullptr;
    this->mParcelableName = std::nullopt;
    int32_t rawDataSize;

    status_t status = p->readInt32(&rawDataSize);
    if (status != android::OK || rawDataSize < 0) {
        this->mParcelPtr = nullptr;
        return status != android::OK ? status : BAD_VALUE;
    }
    if (rawDataSize == 0) {
        if (this->mParcelPtr) {
            this->mParcelPtr = nullptr;
        }
        return OK;
    }

    size_t dataSize = rawDataSize;

    size_t dataStartPos = p->dataPosition();

    if (dataStartPos > SIZE_MAX - dataSize) {
        this->mParcelPtr = nullptr;
        return BAD_VALUE;
    }

    if (!this->mParcelPtr) {
        this->mParcelPtr = std::make_unique<Parcel>();
    }
    this->mParcelPtr->freeData();

    status = this->mParcelPtr->appendFrom(p, dataStartPos, dataSize);
    if (status != android::OK) {
        this->mParcelPtr = nullptr;
        return status;
    }
    p->setDataPosition(dataStartPos + dataSize);
    return OK;
}
} // namespace os
} // namespace android
