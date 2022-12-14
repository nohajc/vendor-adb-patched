/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <android/surface_texture.h>
#include <android/surface_texture_jni.h>

#define LOG_TAG "ASurfaceTexture"

#include <utils/Log.h>

#include <gui/Surface.h>

#include <surfacetexture/surface_texture_platform.h>
#include <surfacetexture/SurfaceTexture.h>

#include <mutex>

#include <jni.h>
#include <nativehelper/scoped_local_ref.h>

struct ASurfaceTexture {
    android::sp<android::SurfaceTexture> consumer;
    android::sp<android::IGraphicBufferProducer> producer;
};

using namespace android;

const char* const kSurfaceTextureClassPathName = "android/graphics/SurfaceTexture";

struct fields_t {
    jfieldID  surfaceTexture;
    jfieldID  producer;
};
static fields_t fields;
static std::once_flag sInitFieldsOnce;

#define ANDROID_GRAPHICS_SURFACETEXTURE_JNI_ID "mSurfaceTexture"
#define ANDROID_GRAPHICS_PRODUCER_JNI_ID "mProducer"

static void SurfaceTexture_classInit(JNIEnv* env, jclass clazz)
{
    fields.surfaceTexture = env->GetFieldID(clazz,
            ANDROID_GRAPHICS_SURFACETEXTURE_JNI_ID, "J");
    if (fields.surfaceTexture == NULL) {
        ALOGE("can't find android/graphics/SurfaceTexture.%s",
                ANDROID_GRAPHICS_SURFACETEXTURE_JNI_ID);
    }
    fields.producer = env->GetFieldID(clazz,
            ANDROID_GRAPHICS_PRODUCER_JNI_ID, "J");
    if (fields.producer == NULL) {
        ALOGE("can't find android/graphics/SurfaceTexture.%s",
                ANDROID_GRAPHICS_PRODUCER_JNI_ID);
    }
}

static inline jclass FindClassOrDie(JNIEnv* env, const char* class_name) {
    jclass clazz = env->FindClass(class_name);
    LOG_ALWAYS_FATAL_IF(clazz == NULL, "Unable to find class %s", class_name);
    return clazz;
}

static void register_android_graphics_SurfaceTexture(JNIEnv* env)
{
    // Cache some fields.
    ScopedLocalRef<jclass> klass(env, FindClassOrDie(env, kSurfaceTextureClassPathName));
    SurfaceTexture_classInit(env, klass.get());
}

static bool android_SurfaceTexture_isInstanceOf(JNIEnv* env, jobject thiz) {
    std::call_once(sInitFieldsOnce, [=]() {
        register_android_graphics_SurfaceTexture(env);
    });

    jclass surfaceTextureClass = env->FindClass(kSurfaceTextureClassPathName);
    return env->IsInstanceOf(thiz, surfaceTextureClass);
}

static sp<SurfaceTexture> SurfaceTexture_getSurfaceTexture(JNIEnv* env, jobject thiz) {
    std::call_once(sInitFieldsOnce, [=]() {
        register_android_graphics_SurfaceTexture(env);
    });

    return (SurfaceTexture*)env->GetLongField(thiz, fields.surfaceTexture);
}

static sp<IGraphicBufferProducer> SurfaceTexture_getProducer(JNIEnv* env, jobject thiz) {
    std::call_once(sInitFieldsOnce, [=]() {
        register_android_graphics_SurfaceTexture(env);
    });

    return (IGraphicBufferProducer*)env->GetLongField(thiz, fields.producer);
}

// The following functions implement NDK API.
ASurfaceTexture* ASurfaceTexture_fromSurfaceTexture(JNIEnv* env, jobject surfacetexture) {
    if (!surfacetexture || !android_SurfaceTexture_isInstanceOf(env, surfacetexture)) {
        return nullptr;
    }
    ASurfaceTexture* ast = new ASurfaceTexture;
    ast->consumer = SurfaceTexture_getSurfaceTexture(env, surfacetexture);
    ast->producer = SurfaceTexture_getProducer(env, surfacetexture);
    return ast;
}

ANativeWindow* ASurfaceTexture_acquireANativeWindow(ASurfaceTexture* st) {
    sp<Surface> surface = new Surface(st->producer);
    ANativeWindow* win(surface.get());
    ANativeWindow_acquire(win);
    return win;
}

void ASurfaceTexture_release(ASurfaceTexture* st) {
    delete st;
}

int ASurfaceTexture_attachToGLContext(ASurfaceTexture* st, uint32_t tex) {
    return st->consumer->attachToContext(tex);
}

int ASurfaceTexture_detachFromGLContext(ASurfaceTexture* st) {
    return st->consumer->detachFromContext();
}

int ASurfaceTexture_updateTexImage(ASurfaceTexture* st) {
    return st->consumer->updateTexImage();
}

void ASurfaceTexture_getTransformMatrix(ASurfaceTexture* st, float mtx[16]) {
    st->consumer->getTransformMatrix(mtx);
}

int64_t ASurfaceTexture_getTimestamp(ASurfaceTexture* st) {
    return st->consumer->getTimestamp();
}

// The following functions are private/unstable API.
namespace android {
ANativeWindow* ASurfaceTexture_routeAcquireANativeWindow(ASurfaceTexture* st) {
    return ASurfaceTexture_acquireANativeWindow(st);
}

int ASurfaceTexture_routeAttachToGLContext(ASurfaceTexture* st, uint32_t texName) {
    return ASurfaceTexture_attachToGLContext(st, texName);
}

void ASurfaceTexture_routeRelease(ASurfaceTexture* st) {
    return ASurfaceTexture_release(st);
}

int ASurfaceTexture_routeDetachFromGLContext(ASurfaceTexture* st) {
    return ASurfaceTexture_detachFromGLContext(st);
}

int ASurfaceTexture_routeUpdateTexImage(ASurfaceTexture* st) {
    return ASurfaceTexture_updateTexImage(st);
}

void ASurfaceTexture_routeGetTransformMatrix(ASurfaceTexture* st, float mtx[16]) {
    return ASurfaceTexture_getTransformMatrix(st, mtx);
}

int64_t ASurfaceTexture_routeGetTimestamp(ASurfaceTexture* st) {
    return ASurfaceTexture_getTimestamp(st);
}

ASurfaceTexture* ASurfaceTexture_routeFromSurfaceTexture(JNIEnv* env, jobject surfacetexture) {
    return ASurfaceTexture_fromSurfaceTexture(env, surfacetexture);
}

unsigned int ASurfaceTexture_getCurrentTextureTarget(ASurfaceTexture* st) {
    return st->consumer->getCurrentTextureTarget();
}

void ASurfaceTexture_takeConsumerOwnership(ASurfaceTexture* texture) {
    texture->consumer->takeConsumerOwnership();
}

void ASurfaceTexture_releaseConsumerOwnership(ASurfaceTexture* texture) {
    texture->consumer->releaseConsumerOwnership();
}

AHardwareBuffer* ASurfaceTexture_dequeueBuffer(ASurfaceTexture* st, int* outSlotid,
                                               android_dataspace* outDataspace,
                                               float* outTransformMatrix, bool* outNewContent,
                                               ASurfaceTexture_createReleaseFence createFence,
                                               ASurfaceTexture_fenceWait fenceWait, void* handle) {
    sp<GraphicBuffer> buffer;
    *outNewContent = false;
    bool queueEmpty;
    do {
        buffer = st->consumer->dequeueBuffer(outSlotid, outDataspace, outTransformMatrix,
                                             &queueEmpty, createFence, fenceWait, handle);
        if (!queueEmpty) {
            *outNewContent = true;
        }
    } while (buffer.get() && (!queueEmpty));
    AHardwareBuffer* result = nullptr;
    if (buffer.get()) {
      result = buffer->toAHardwareBuffer();
      // add a reference to keep the hardware buffer alive, even if
      // BufferQueueProducer is disconnected. This is needed, because
      // sp reference is destroyed at the end of this function.
      AHardwareBuffer_acquire(result);
    }
    return result;
}

} // namespace android
