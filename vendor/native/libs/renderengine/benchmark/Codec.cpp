/*
 * Copyright 2021 The Android Open Source Project
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

#include <RenderEngineBench.h>
#include <android/bitmap.h>
#include <android/data_space.h>
#include <android/imagedecoder.h>
#include <log/log.h>
#include <renderengine/ExternalTexture.h>
#include <renderengine/RenderEngine.h>
#include <sys/types.h>

using namespace android;
using namespace android::renderengine;

namespace {
struct DecoderDeleter {
    void operator()(AImageDecoder* decoder) { AImageDecoder_delete(decoder); }
};

using AutoDecoderDeleter = std::unique_ptr<AImageDecoder, DecoderDeleter>;

bool ok(int aImageDecoderResult, const char* path, const char* method) {
    if (aImageDecoderResult == ANDROID_IMAGE_DECODER_SUCCESS) {
        return true;
    }

    ALOGE("Failed AImageDecoder_%s on '%s' with error '%s'", method, path,
          AImageDecoder_resultToString(aImageDecoderResult));
    return false;
}
} // namespace

namespace renderenginebench {

void decode(const char* path, const sp<GraphicBuffer>& buffer) {
    base::unique_fd fd{open(path, O_RDONLY)};
    if (fd.get() < 0) {
        ALOGE("Failed to open %s", path);
        return;
    }

    AImageDecoder* decoder{nullptr};
    auto result = AImageDecoder_createFromFd(fd.get(), &decoder);
    if (!ok(result, path, "createFromFd")) {
        return;
    }

    AutoDecoderDeleter deleter(decoder);

    LOG_ALWAYS_FATAL_IF(buffer->getWidth() <= 0 || buffer->getHeight() <= 0,
                        "Impossible buffer size!");
    auto width = static_cast<int32_t>(buffer->getWidth());
    auto height = static_cast<int32_t>(buffer->getHeight());
    result = AImageDecoder_setTargetSize(decoder, width, height);
    if (!ok(result, path, "setTargetSize")) {
        return;
    }

    void* pixels{nullptr};
    int32_t stride{0};
    if (auto status = buffer->lock(GRALLOC_USAGE_SW_WRITE_OFTEN, &pixels,
                                   nullptr /*outBytesPerPixel*/, &stride);
        status < 0) {
        ALOGE("Failed to lock pixels!");
        return;
    }

    result = AImageDecoder_decodeImage(decoder, pixels, static_cast<size_t>(stride),
                                       static_cast<size_t>(stride * height));
    if (auto status = buffer->unlock(); status < 0) {
        ALOGE("Failed to unlock pixels!");
    }

    // For the side effect of logging.
    (void)ok(result, path, "decodeImage");
}

void encodeToJpeg(const char* path, const sp<GraphicBuffer>& buffer) {
    base::unique_fd fd{open(path, O_WRONLY | O_CREAT, S_IWUSR)};
    if (fd.get() < 0) {
        ALOGE("Failed to open %s", path);
        return;
    }

    void* pixels{nullptr};
    int32_t stride{0};
    if (auto status = buffer->lock(GRALLOC_USAGE_SW_READ_OFTEN, &pixels,
                                   nullptr /*outBytesPerPixel*/, &stride);
        status < 0) {
        ALOGE("Failed to lock pixels!");
        return;
    }

    AndroidBitmapInfo info{
            .width = buffer->getWidth(),
            .height = buffer->getHeight(),
            .stride = static_cast<uint32_t>(stride),
            .format = ANDROID_BITMAP_FORMAT_RGBA_8888,
            .flags = ANDROID_BITMAP_FLAGS_ALPHA_OPAQUE,
    };
    int result = AndroidBitmap_compress(&info, ADATASPACE_SRGB, pixels,
                                        ANDROID_BITMAP_COMPRESS_FORMAT_JPEG, 80, &fd,
                                        [](void* fdPtr, const void* data, size_t size) -> bool {
                                            const ssize_t bytesWritten =
                                                    write(reinterpret_cast<base::unique_fd*>(fdPtr)
                                                                  ->get(),
                                                          data, size);
                                            return bytesWritten > 0 &&
                                                    static_cast<size_t>(bytesWritten) == size;
                                        });
    if (result == ANDROID_BITMAP_RESULT_SUCCESS) {
        ALOGD("Successfully encoded to '%s'", path);
    } else {
        ALOGE("Failed to encode to %s with error %d", path, result);
    }

    if (auto status = buffer->unlock(); status < 0) {
        ALOGE("Failed to unlock pixels!");
    }
}

} // namespace renderenginebench
