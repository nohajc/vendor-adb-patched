/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <type_traits>
#define LOG_TAG "WindowInfo"
#define LOG_NDEBUG 0

#include <android-base/stringprintf.h>
#include <binder/Parcel.h>
#include <gui/WindowInfo.h>

#include <log/log.h>

namespace android::gui {

// --- WindowInfo ---
void WindowInfo::addTouchableRegion(const Rect& region) {
    touchableRegion.orSelf(region);
}

bool WindowInfo::touchableRegionContainsPoint(int32_t x, int32_t y) const {
    return touchableRegion.contains(x, y);
}

bool WindowInfo::frameContainsPoint(int32_t x, int32_t y) const {
    return x >= frameLeft && x < frameRight && y >= frameTop && y < frameBottom;
}

bool WindowInfo::supportsSplitTouch() const {
    return flags.test(Flag::SPLIT_TOUCH);
}

bool WindowInfo::overlaps(const WindowInfo* other) const {
    return frameLeft < other->frameRight && frameRight > other->frameLeft &&
            frameTop < other->frameBottom && frameBottom > other->frameTop;
}

bool WindowInfo::operator==(const WindowInfo& info) const {
    return info.token == token && info.id == id && info.name == name && info.flags == flags &&
            info.type == type && info.dispatchingTimeout == dispatchingTimeout &&
            info.frameLeft == frameLeft && info.frameTop == frameTop &&
            info.frameRight == frameRight && info.frameBottom == frameBottom &&
            info.surfaceInset == surfaceInset && info.globalScaleFactor == globalScaleFactor &&
            info.transform == transform && info.displayOrientation == displayOrientation &&
            info.displayWidth == displayWidth && info.displayHeight == displayHeight &&
            info.touchableRegion.hasSameRects(touchableRegion) && info.visible == visible &&
            info.trustedOverlay == trustedOverlay && info.focusable == focusable &&
            info.touchOcclusionMode == touchOcclusionMode && info.hasWallpaper == hasWallpaper &&
            info.paused == paused && info.ownerPid == ownerPid && info.ownerUid == ownerUid &&
            info.packageName == packageName && info.inputFeatures == inputFeatures &&
            info.displayId == displayId && info.portalToDisplayId == portalToDisplayId &&
            info.replaceTouchableRegionWithCrop == replaceTouchableRegionWithCrop &&
            info.applicationInfo == applicationInfo;
}

status_t WindowInfo::writeToParcel(android::Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }
    if (name.empty()) {
        parcel->writeInt32(0);
        return OK;
    }
    parcel->writeInt32(1);

    // clang-format off
    status_t status = parcel->writeStrongBinder(token) ?:
        parcel->writeInt64(dispatchingTimeout.count()) ?:
        parcel->writeInt32(id) ?:
        parcel->writeUtf8AsUtf16(name) ?:
        parcel->writeInt32(flags.get()) ?:
        parcel->writeInt32(static_cast<std::underlying_type_t<WindowInfo::Type>>(type)) ?:
        parcel->writeInt32(frameLeft) ?:
        parcel->writeInt32(frameTop) ?:
        parcel->writeInt32(frameRight) ?:
        parcel->writeInt32(frameBottom) ?:
        parcel->writeInt32(surfaceInset) ?:
        parcel->writeFloat(globalScaleFactor) ?:
        parcel->writeFloat(alpha) ?:
        parcel->writeFloat(transform.dsdx()) ?:
        parcel->writeFloat(transform.dtdx()) ?:
        parcel->writeFloat(transform.tx()) ?:
        parcel->writeFloat(transform.dtdy()) ?:
        parcel->writeFloat(transform.dsdy()) ?:
        parcel->writeFloat(transform.ty()) ?:
        parcel->writeUint32(displayOrientation) ?:
        parcel->writeInt32(displayWidth) ?:
        parcel->writeInt32(displayHeight) ?:
        parcel->writeBool(visible) ?:
        parcel->writeBool(focusable) ?:
        parcel->writeBool(hasWallpaper) ?:
        parcel->writeBool(paused) ?:
        parcel->writeBool(trustedOverlay) ?:
        parcel->writeInt32(static_cast<int32_t>(touchOcclusionMode)) ?:
        parcel->writeInt32(ownerPid) ?:
        parcel->writeInt32(ownerUid) ?:
        parcel->writeUtf8AsUtf16(packageName) ?:
        parcel->writeInt32(inputFeatures.get()) ?:
        parcel->writeInt32(displayId) ?:
        parcel->writeInt32(portalToDisplayId) ?:
        applicationInfo.writeToParcel(parcel) ?:
        parcel->write(touchableRegion) ?:
        parcel->writeBool(replaceTouchableRegionWithCrop) ?:
        parcel->writeStrongBinder(touchableRegionCropHandle.promote()) ?:
        parcel->writeStrongBinder(windowToken);
    // clang-format on
    return status;
}

status_t WindowInfo::readFromParcel(const android::Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }
    if (parcel->readInt32() == 0) {
        return OK;
    }

    token = parcel->readStrongBinder();
    dispatchingTimeout = static_cast<decltype(dispatchingTimeout)>(parcel->readInt64());
    status_t status = parcel->readInt32(&id) ?: parcel->readUtf8FromUtf16(&name);
    if (status != OK) {
        return status;
    }

    flags = Flags<Flag>(parcel->readInt32());
    type = static_cast<Type>(parcel->readInt32());
    float dsdx, dtdx, tx, dtdy, dsdy, ty;
    int32_t touchOcclusionModeInt;
    // clang-format off
    status = parcel->readInt32(&frameLeft) ?:
        parcel->readInt32(&frameTop) ?:
        parcel->readInt32(&frameRight) ?:
        parcel->readInt32(&frameBottom) ?:
        parcel->readInt32(&surfaceInset) ?:
        parcel->readFloat(&globalScaleFactor) ?:
        parcel->readFloat(&alpha) ?:
        parcel->readFloat(&dsdx) ?:
        parcel->readFloat(&dtdx) ?:
        parcel->readFloat(&tx) ?:
        parcel->readFloat(&dtdy) ?:
        parcel->readFloat(&dsdy) ?:
        parcel->readFloat(&ty) ?:
        parcel->readUint32(&displayOrientation) ?:
        parcel->readInt32(&displayWidth) ?:
        parcel->readInt32(&displayHeight) ?:
        parcel->readBool(&visible) ?:
        parcel->readBool(&focusable) ?:
        parcel->readBool(&hasWallpaper) ?:
        parcel->readBool(&paused) ?:
        parcel->readBool(&trustedOverlay) ?:
        parcel->readInt32(&touchOcclusionModeInt) ?:
        parcel->readInt32(&ownerPid) ?:
        parcel->readInt32(&ownerUid) ?:
        parcel->readUtf8FromUtf16(&packageName);
    // clang-format on

    if (status != OK) {
        return status;
    }

    touchOcclusionMode = static_cast<TouchOcclusionMode>(touchOcclusionModeInt);

    inputFeatures = Flags<Feature>(parcel->readInt32());
    // clang-format off
    status = parcel->readInt32(&displayId) ?:
        parcel->readInt32(&portalToDisplayId) ?:
        applicationInfo.readFromParcel(parcel) ?:
        parcel->read(touchableRegion) ?:
        parcel->readBool(&replaceTouchableRegionWithCrop);
    // clang-format on

    if (status != OK) {
        return status;
    }

    touchableRegionCropHandle = parcel->readStrongBinder();
    transform.set({dsdx, dtdx, tx, dtdy, dsdy, ty, 0, 0, 1});

    status = parcel->readNullableStrongBinder(&windowToken);
    return status;
}

// --- WindowInfoHandle ---

WindowInfoHandle::WindowInfoHandle() {}

WindowInfoHandle::~WindowInfoHandle() {}

WindowInfoHandle::WindowInfoHandle(const WindowInfoHandle& other) : mInfo(other.mInfo) {}

WindowInfoHandle::WindowInfoHandle(const WindowInfo& other) : mInfo(other) {}

status_t WindowInfoHandle::writeToParcel(android::Parcel* parcel) const {
    return mInfo.writeToParcel(parcel);
}

status_t WindowInfoHandle::readFromParcel(const android::Parcel* parcel) {
    return mInfo.readFromParcel(parcel);
}

void WindowInfoHandle::releaseChannel() {
    mInfo.token.clear();
}

sp<IBinder> WindowInfoHandle::getToken() const {
    return mInfo.token;
}

void WindowInfoHandle::updateFrom(sp<WindowInfoHandle> handle) {
    mInfo = handle->mInfo;
}
} // namespace android::gui
