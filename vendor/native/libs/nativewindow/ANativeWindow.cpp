/*
 * Copyright (C) 2010 The Android Open Source Project
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

#define LOG_TAG "ANativeWindow"

#include <grallocusage/GrallocUsageConversion.h>
// from nativewindow/includes/system/window.h
// (not to be confused with the compatibility-only window.h from system/core/includes)
#include <system/window.h>
#include <android/native_window_aidl.h>

#include <private/android/AHardwareBufferHelpers.h>

#include <android/binder_libbinder.h>
#include <dlfcn.h>
#include <log/log.h>
#include <ui/GraphicBuffer.h>

using namespace android;

#if defined(__ANDROID_APEX__) || defined(__ANDROID_VNDK__)
#error libnativewindow can only be built for system
#endif

using android_view_Surface_writeToParcel = status_t (*)(ANativeWindow* _Nonnull window,
                                                        Parcel* _Nonnull parcel);

using android_view_Surface_readFromParcel =
        status_t (*)(const Parcel* _Nonnull parcel, ANativeWindow* _Nullable* _Nonnull outWindow);

struct SurfaceParcelables {
    android_view_Surface_writeToParcel write = nullptr;
    android_view_Surface_readFromParcel read = nullptr;
};

const SurfaceParcelables* getSurfaceParcelFunctions() {
    static SurfaceParcelables funcs = []() -> SurfaceParcelables {
        SurfaceParcelables ret;
        void* dl = dlopen("libgui.so", RTLD_NOW);
        LOG_ALWAYS_FATAL_IF(!dl, "Failed to find libgui.so");
        ret.write =
                (android_view_Surface_writeToParcel)dlsym(dl, "android_view_Surface_writeToParcel");
        LOG_ALWAYS_FATAL_IF(!ret.write,
                            "libgui.so missing android_view_Surface_writeToParcel; "
                            "loaded wrong libgui?");
        ret.read =
                (android_view_Surface_readFromParcel)dlsym(dl,
                                                           "android_view_Surface_readFromParcel");
        LOG_ALWAYS_FATAL_IF(!ret.read,
                            "libgui.so missing android_view_Surface_readFromParcel; "
                            "loaded wrong libgui?");
        return ret;
    }();
    return &funcs;
}

static int32_t query(ANativeWindow* window, int what) {
    int value;
    int res = window->query(window, what, &value);
    return res < 0 ? res : value;
}

static int64_t query64(ANativeWindow* window, int what) {
    int64_t value;
    int res = window->perform(window, what, &value);
    return res < 0 ? res : value;
}

static bool isDataSpaceValid(ANativeWindow* window, int32_t dataSpace) {
    bool supported = false;
    switch (dataSpace) {
        case HAL_DATASPACE_UNKNOWN:
        case HAL_DATASPACE_V0_SRGB:
            return true;
        // These data space need wide gamut support.
        case HAL_DATASPACE_V0_SCRGB_LINEAR:
        case HAL_DATASPACE_V0_SCRGB:
        case HAL_DATASPACE_DISPLAY_P3:
            native_window_get_wide_color_support(window, &supported);
            return supported;
        // These data space need HDR support.
        case HAL_DATASPACE_BT2020_PQ:
            native_window_get_hdr_support(window, &supported);
            return supported;
        default:
            return false;
    }
}

/**************************************************************************************************
 * NDK
 **************************************************************************************************/

void ANativeWindow_acquire(ANativeWindow* window) {
    // incStrong/decStrong token must be the same, doesn't matter what it is
    window->incStrong((void*)ANativeWindow_acquire);
}

void ANativeWindow_release(ANativeWindow* window) {
    // incStrong/decStrong token must be the same, doesn't matter what it is
    window->decStrong((void*)ANativeWindow_acquire);
}

int32_t ANativeWindow_getWidth(ANativeWindow* window) {
    return query(window, NATIVE_WINDOW_WIDTH);
}

int32_t ANativeWindow_getHeight(ANativeWindow* window) {
    return query(window, NATIVE_WINDOW_HEIGHT);
}

int32_t ANativeWindow_getFormat(ANativeWindow* window) {
    return query(window, NATIVE_WINDOW_FORMAT);
}

int32_t ANativeWindow_setBuffersGeometry(ANativeWindow* window,
        int32_t width, int32_t height, int32_t format) {
    int32_t err = native_window_set_buffers_format(window, format);
    if (!err) {
        err = native_window_set_buffers_user_dimensions(window, width, height);
        if (!err) {
            int mode = NATIVE_WINDOW_SCALING_MODE_FREEZE;
            if (width && height) {
                mode = NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
            }
            err = native_window_set_scaling_mode(window, mode);
        }
    }
    return err;
}

int32_t ANativeWindow_lock(ANativeWindow* window, ANativeWindow_Buffer* outBuffer,
        ARect* inOutDirtyBounds) {
    return window->perform(window, NATIVE_WINDOW_LOCK, outBuffer, inOutDirtyBounds);
}

int32_t ANativeWindow_unlockAndPost(ANativeWindow* window) {
    return window->perform(window, NATIVE_WINDOW_UNLOCK_AND_POST);
}

int32_t ANativeWindow_setBuffersTransform(ANativeWindow* window, int32_t transform) {
    static_assert(ANATIVEWINDOW_TRANSFORM_MIRROR_HORIZONTAL == NATIVE_WINDOW_TRANSFORM_FLIP_H);
    static_assert(ANATIVEWINDOW_TRANSFORM_MIRROR_VERTICAL == NATIVE_WINDOW_TRANSFORM_FLIP_V);
    static_assert(ANATIVEWINDOW_TRANSFORM_ROTATE_90 == NATIVE_WINDOW_TRANSFORM_ROT_90);

    constexpr int32_t kAllTransformBits =
            ANATIVEWINDOW_TRANSFORM_MIRROR_HORIZONTAL |
            ANATIVEWINDOW_TRANSFORM_MIRROR_VERTICAL |
            ANATIVEWINDOW_TRANSFORM_ROTATE_90 |
            // We don't expose INVERSE_DISPLAY as an NDK constant, but someone could have read it
            // from a buffer already set by Camera framework, so we allow it to be forwarded.
            NATIVE_WINDOW_TRANSFORM_INVERSE_DISPLAY;
    if (!window || !query(window, NATIVE_WINDOW_IS_VALID))
        return -EINVAL;
    if ((transform & ~kAllTransformBits) != 0)
        return -EINVAL;

    return native_window_set_buffers_transform(window, transform);
}

int32_t ANativeWindow_setBuffersDataSpace(ANativeWindow* window, int32_t dataSpace) {
    static_assert(static_cast<int>(ADATASPACE_UNKNOWN) == static_cast<int>(HAL_DATASPACE_UNKNOWN));
    static_assert(static_cast<int>(STANDARD_MASK) == static_cast<int>(HAL_DATASPACE_STANDARD_MASK));
    static_assert(static_cast<int>(STANDARD_UNSPECIFIED) == static_cast<int>(HAL_DATASPACE_STANDARD_UNSPECIFIED));
    static_assert(static_cast<int>(STANDARD_BT709) == static_cast<int>(HAL_DATASPACE_STANDARD_BT709));
    static_assert(static_cast<int>(STANDARD_BT601_625) == static_cast<int>(HAL_DATASPACE_STANDARD_BT601_625));
    static_assert(static_cast<int>(STANDARD_BT601_625_UNADJUSTED) == static_cast<int>(HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED));
    static_assert(static_cast<int>(STANDARD_BT601_525) == static_cast<int>(HAL_DATASPACE_STANDARD_BT601_525));
    static_assert(static_cast<int>(STANDARD_BT601_525_UNADJUSTED) == static_cast<int>(HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED));
    static_assert(static_cast<int>(STANDARD_BT470M) == static_cast<int>(HAL_DATASPACE_STANDARD_BT470M));
    static_assert(static_cast<int>(STANDARD_FILM) == static_cast<int>(HAL_DATASPACE_STANDARD_FILM));
    static_assert(static_cast<int>(STANDARD_DCI_P3) == static_cast<int>(HAL_DATASPACE_STANDARD_DCI_P3));
    static_assert(static_cast<int>(STANDARD_ADOBE_RGB) == static_cast<int>(HAL_DATASPACE_STANDARD_ADOBE_RGB));
    static_assert(static_cast<int>(TRANSFER_MASK) == static_cast<int>(HAL_DATASPACE_TRANSFER_MASK));
    static_assert(static_cast<int>(TRANSFER_UNSPECIFIED) == static_cast<int>(HAL_DATASPACE_TRANSFER_UNSPECIFIED));
    static_assert(static_cast<int>(TRANSFER_LINEAR) == static_cast<int>(HAL_DATASPACE_TRANSFER_LINEAR));
    static_assert(static_cast<int>(TRANSFER_SMPTE_170M) == static_cast<int>(HAL_DATASPACE_TRANSFER_SMPTE_170M));
    static_assert(static_cast<int>(TRANSFER_GAMMA2_2) == static_cast<int>(HAL_DATASPACE_TRANSFER_GAMMA2_2));
    static_assert(static_cast<int>(TRANSFER_GAMMA2_6) == static_cast<int>(HAL_DATASPACE_TRANSFER_GAMMA2_6));
    static_assert(static_cast<int>(TRANSFER_GAMMA2_8) == static_cast<int>(HAL_DATASPACE_TRANSFER_GAMMA2_8));
    static_assert(static_cast<int>(TRANSFER_ST2084) == static_cast<int>(HAL_DATASPACE_TRANSFER_ST2084));
    static_assert(static_cast<int>(TRANSFER_HLG) == static_cast<int>(HAL_DATASPACE_TRANSFER_HLG));
    static_assert(static_cast<int>(RANGE_MASK) == static_cast<int>(HAL_DATASPACE_RANGE_MASK));
    static_assert(static_cast<int>(RANGE_UNSPECIFIED) == static_cast<int>(HAL_DATASPACE_RANGE_UNSPECIFIED));
    static_assert(static_cast<int>(RANGE_FULL) == static_cast<int>(HAL_DATASPACE_RANGE_FULL));
    static_assert(static_cast<int>(RANGE_LIMITED) == static_cast<int>(HAL_DATASPACE_RANGE_LIMITED));
    static_assert(static_cast<int>(RANGE_EXTENDED) == static_cast<int>(HAL_DATASPACE_RANGE_EXTENDED));
    static_assert(static_cast<int>(ADATASPACE_SRGB) == static_cast<int>(HAL_DATASPACE_V0_SRGB));
    static_assert(static_cast<int>(ADATASPACE_SCRGB) == static_cast<int>(HAL_DATASPACE_V0_SCRGB));
    static_assert(static_cast<int>(ADATASPACE_DISPLAY_P3) == static_cast<int>(HAL_DATASPACE_DISPLAY_P3));
    static_assert(static_cast<int>(ADATASPACE_BT2020_PQ) == static_cast<int>(HAL_DATASPACE_BT2020_PQ));
    static_assert(static_cast<int>(ADATASPACE_BT2020_ITU_PQ) ==
        static_cast<int>(HAL_DATASPACE_BT2020_ITU_PQ));
    static_assert(static_cast<int>(ADATASPACE_ADOBE_RGB) == static_cast<int>(HAL_DATASPACE_ADOBE_RGB));
    static_assert(static_cast<int>(ADATASPACE_JFIF) == static_cast<int>(HAL_DATASPACE_V0_JFIF));
    static_assert(static_cast<int>(ADATASPACE_BT601_625) == static_cast<int>(HAL_DATASPACE_V0_BT601_625));
    static_assert(static_cast<int>(ADATASPACE_BT601_525) == static_cast<int>(HAL_DATASPACE_V0_BT601_525));
    static_assert(static_cast<int>(ADATASPACE_BT2020) == static_cast<int>(HAL_DATASPACE_BT2020));
    static_assert(static_cast<int>(ADATASPACE_BT709) == static_cast<int>(HAL_DATASPACE_V0_BT709));
    static_assert(static_cast<int>(ADATASPACE_DCI_P3) == static_cast<int>(HAL_DATASPACE_DCI_P3));
    static_assert(static_cast<int>(ADATASPACE_SRGB_LINEAR) == static_cast<int>(HAL_DATASPACE_V0_SRGB_LINEAR));
    static_assert(static_cast<int>(ADATASPACE_BT2020_HLG) ==
        static_cast<int>(HAL_DATASPACE_BT2020_HLG));
    static_assert(static_cast<int>(ADATASPACE_BT2020_ITU_HLG) ==
        static_cast<int>(HAL_DATASPACE_BT2020_ITU_HLG));
    static_assert(static_cast<int>(DEPTH) == static_cast<int>(HAL_DATASPACE_DEPTH));
    static_assert(static_cast<int>(DYNAMIC_DEPTH) == static_cast<int>(HAL_DATASPACE_DYNAMIC_DEPTH));

    if (!window || !query(window, NATIVE_WINDOW_IS_VALID) ||
            !isDataSpaceValid(window, dataSpace)) {
        return -EINVAL;
    }
    return native_window_set_buffers_data_space(window,
                                                static_cast<android_dataspace_t>(dataSpace));
}

int32_t ANativeWindow_getBuffersDataSpace(ANativeWindow* window) {
    if (!window || !query(window, NATIVE_WINDOW_IS_VALID))
        return -EINVAL;
    return query(window, NATIVE_WINDOW_DATASPACE);
}

int32_t ANativeWindow_setFrameRate(ANativeWindow* window, float frameRate, int8_t compatibility) {
    return ANativeWindow_setFrameRateWithChangeStrategy(window, frameRate, compatibility,
        ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS);
}

void ANativeWindow_tryAllocateBuffers(ANativeWindow* window) {
    if (!window || !query(window, NATIVE_WINDOW_IS_VALID)) {
        return;
    }
    window->perform(window, NATIVE_WINDOW_ALLOCATE_BUFFERS);
}

int32_t ANativeWindow_setFrameRateWithChangeStrategy(ANativeWindow* window, float frameRate,
        int8_t compatibility, int8_t changeFrameRateStrategy) {
    if (!window || !query(window, NATIVE_WINDOW_IS_VALID)) {
        return -EINVAL;
    }
    return native_window_set_frame_rate(window, frameRate, compatibility, changeFrameRateStrategy);
}

/**************************************************************************************************
 * vndk-stable
 **************************************************************************************************/

AHardwareBuffer* ANativeWindowBuffer_getHardwareBuffer(ANativeWindowBuffer* anwb) {
    return AHardwareBuffer_from_GraphicBuffer(static_cast<GraphicBuffer*>(anwb));
}

int ANativeWindow_OemStorageSet(ANativeWindow* window, uint32_t slot, intptr_t value) {
    if (slot < 4) {
        window->oem[slot] = value;
        return 0;
    }
    return -EINVAL;
}

int ANativeWindow_OemStorageGet(ANativeWindow* window, uint32_t slot, intptr_t* value) {
    if (slot >= 4) {
        *value = window->oem[slot];
        return 0;
    }
    return -EINVAL;
}


int ANativeWindow_setSwapInterval(ANativeWindow* window, int interval) {
    return window->setSwapInterval(window, interval);
}

int ANativeWindow_query(const ANativeWindow* window, ANativeWindowQuery what, int* value) {
    switch (what) {
        case ANATIVEWINDOW_QUERY_MIN_UNDEQUEUED_BUFFERS:
        case ANATIVEWINDOW_QUERY_DEFAULT_WIDTH:
        case ANATIVEWINDOW_QUERY_DEFAULT_HEIGHT:
        case ANATIVEWINDOW_QUERY_TRANSFORM_HINT:
        case ANATIVEWINDOW_QUERY_BUFFER_AGE:
            // these are part of the VNDK API
            break;
        case ANATIVEWINDOW_QUERY_MIN_SWAP_INTERVAL:
            *value = window->minSwapInterval;
            return 0;
        case ANATIVEWINDOW_QUERY_MAX_SWAP_INTERVAL:
            *value = window->maxSwapInterval;
            return 0;
        case ANATIVEWINDOW_QUERY_XDPI:
            *value = (int)window->xdpi;
            return 0;
        case ANATIVEWINDOW_QUERY_YDPI:
            *value = (int)window->ydpi;
            return 0;
        default:
            // asked for an invalid query(), one that isn't part of the VNDK
            return -EINVAL;
    }
    return window->query(window, int(what), value);
}

int ANativeWindow_queryf(const ANativeWindow* window, ANativeWindowQuery what, float* value) {
    switch (what) {
        case ANATIVEWINDOW_QUERY_XDPI:
            *value = window->xdpi;
            return 0;
        case ANATIVEWINDOW_QUERY_YDPI:
            *value = window->ydpi;
            return 0;
        default:
            break;
    }

    int i;
    int e = ANativeWindow_query(window, what, &i);
    if (e == 0) {
        *value = (float)i;
    }
    return e;
}

int ANativeWindow_dequeueBuffer(ANativeWindow* window, ANativeWindowBuffer** buffer, int* fenceFd) {
    return window->dequeueBuffer(window, buffer, fenceFd);
}

int ANativeWindow_queueBuffer(ANativeWindow* window, ANativeWindowBuffer* buffer, int fenceFd) {
    return window->queueBuffer(window, buffer, fenceFd);
}

int ANativeWindow_cancelBuffer(ANativeWindow* window, ANativeWindowBuffer* buffer, int fenceFd) {
    return window->cancelBuffer(window, buffer, fenceFd);
}

int ANativeWindow_setUsage(ANativeWindow* window, uint64_t usage) {
    return native_window_set_usage(window, usage);
}

int ANativeWindow_setBufferCount(ANativeWindow* window, size_t bufferCount) {
    return native_window_set_buffer_count(window, bufferCount);
}

int ANativeWindow_setBuffersDimensions(ANativeWindow* window, uint32_t w, uint32_t h) {
    return native_window_set_buffers_dimensions(window, (int)w, (int)h);
}

int ANativeWindow_setBuffersFormat(ANativeWindow* window, int format) {
    return native_window_set_buffers_format(window, format);
}

int ANativeWindow_setBuffersTimestamp(ANativeWindow* window, int64_t timestamp) {
    return native_window_set_buffers_timestamp(window, timestamp);
}

int ANativeWindow_setSharedBufferMode(ANativeWindow* window, bool sharedBufferMode) {
    return native_window_set_shared_buffer_mode(window, sharedBufferMode);
}

int ANativeWindow_setAutoRefresh(ANativeWindow* window, bool autoRefresh) {
    return native_window_set_auto_refresh(window, autoRefresh);
}

int ANativeWindow_setAutoPrerotation(ANativeWindow* window, bool autoPrerotation) {
    return native_window_set_auto_prerotation(window, autoPrerotation);
}

binder_status_t ANativeWindow_readFromParcel(
        const AParcel* _Nonnull parcel, ANativeWindow* _Nullable* _Nonnull outWindow) {
    auto funcs = getSurfaceParcelFunctions();
    if (funcs->read == nullptr) {
        ALOGE("Failed to load Surface_readFromParcel implementation");
        return STATUS_FAILED_TRANSACTION;
    }
    const Parcel* nativeParcel = AParcel_viewPlatformParcel(parcel);
    return funcs->read(nativeParcel, outWindow);
}

binder_status_t ANativeWindow_writeToParcel(
        ANativeWindow* _Nonnull window, AParcel* _Nonnull parcel) {
    auto funcs = getSurfaceParcelFunctions();
    if (funcs->write == nullptr) {
        ALOGE("Failed to load Surface_writeToParcel implementation");
        return STATUS_FAILED_TRANSACTION;
    }
    Parcel* nativeParcel = AParcel_viewPlatformParcel(parcel);
    return funcs->write(window, nativeParcel);
}

/**************************************************************************************************
 * apex-stable
 **************************************************************************************************/

int64_t ANativeWindow_getLastDequeueDuration(ANativeWindow* window) {
    return query64(window, NATIVE_WINDOW_GET_LAST_DEQUEUE_DURATION);
}

int64_t ANativeWindow_getLastQueueDuration(ANativeWindow* window) {
    return query64(window, NATIVE_WINDOW_GET_LAST_QUEUE_DURATION);
}

int64_t ANativeWindow_getLastDequeueStartTime(ANativeWindow* window) {
    return query64(window, NATIVE_WINDOW_GET_LAST_DEQUEUE_START);
}

int ANativeWindow_setDequeueTimeout(ANativeWindow* window, int64_t timeout) {
    return window->perform(window, NATIVE_WINDOW_SET_DEQUEUE_TIMEOUT, timeout);
}

int ANativeWindow_setCancelBufferInterceptor(ANativeWindow* window,
                                             ANativeWindow_cancelBufferInterceptor interceptor,
                                             void* data) {
    return window->perform(window, NATIVE_WINDOW_SET_CANCEL_INTERCEPTOR, interceptor, data);
}

int ANativeWindow_setDequeueBufferInterceptor(ANativeWindow* window,
                                              ANativeWindow_dequeueBufferInterceptor interceptor,
                                              void* data) {
    return window->perform(window, NATIVE_WINDOW_SET_DEQUEUE_INTERCEPTOR, interceptor, data);
}

int ANativeWindow_setPerformInterceptor(ANativeWindow* window,
                                        ANativeWindow_performInterceptor interceptor, void* data) {
    return window->perform(window, NATIVE_WINDOW_SET_PERFORM_INTERCEPTOR, interceptor, data);
}

int ANativeWindow_setQueueBufferInterceptor(ANativeWindow* window,
                                            ANativeWindow_queueBufferInterceptor interceptor,
                                            void* data) {
    return window->perform(window, NATIVE_WINDOW_SET_QUEUE_INTERCEPTOR, interceptor, data);
}
