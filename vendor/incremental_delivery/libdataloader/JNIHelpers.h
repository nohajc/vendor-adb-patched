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

#include <jni.h>
#include <log/log.h>

// JNI helpers.
static inline jclass FindClassOrDie(JNIEnv* env, const char* class_name) {
    jclass clazz = env->FindClass(class_name);
    LOG_ALWAYS_FATAL_IF(clazz == NULL, "Unable to find class %s", class_name);
    return clazz;
}

static inline jmethodID GetMethodIDOrDie(JNIEnv* env, jclass clazz, const char* method_name,
                                         const char* method_signature) {
    jmethodID res = env->GetMethodID(clazz, method_name, method_signature);
    LOG_ALWAYS_FATAL_IF(res == NULL, "Unable to find method %s", method_name);
    return res;
}

static inline jmethodID GetStaticMethodIDOrDie(JNIEnv* env, jclass clazz, const char* method_name,
                                               const char* method_signature) {
    jmethodID res = env->GetStaticMethodID(clazz, method_name, method_signature);
    LOG_ALWAYS_FATAL_IF(res == NULL, "Unable to find static method %s", method_name);
    return res;
}

static inline jfieldID GetFieldIDOrDie(JNIEnv* env, jclass clazz, const char* field_name,
                                       const char* field_signature) {
    jfieldID res = env->GetFieldID(clazz, field_name, field_signature);
    LOG_ALWAYS_FATAL_IF(res == NULL, "Unable to find static field %s", field_name);
    return res;
}

static inline jfieldID GetStaticFieldIDOrDie(JNIEnv* env, jclass clazz, const char* field_name,
                                             const char* field_signature) {
    jfieldID res = env->GetStaticFieldID(clazz, field_name, field_signature);
    LOG_ALWAYS_FATAL_IF(res == NULL, "Unable to find static field %s", field_name);
    return res;
}

static inline jint GetStaticIntFieldValueOrDie(JNIEnv* env, jclass clazz, const char* fieldName) {
    jfieldID res = env->GetStaticFieldID(clazz, fieldName, "I");
    LOG_ALWAYS_FATAL_IF(res == NULL, "Unable to find static field %s", fieldName);
    return env->GetStaticIntField(clazz, res);
}

static inline jstring GetStringField(JNIEnv* env, jobject obj, jfieldID field) {
    return reinterpret_cast<jstring>(env->GetObjectField(obj, field));
}

static inline jbyteArray GetByteArrayField(JNIEnv* env, jobject obj, jfieldID field) {
    return reinterpret_cast<jbyteArray>(env->GetObjectField(obj, field));
}

static inline JNIEnv* GetJNIEnvironment(JavaVM* vm) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return 0;
    }
    return env;
}

static inline JNIEnv* GetOrAttachJNIEnvironment(JavaVM* jvm) {
    JNIEnv* env = GetJNIEnvironment(jvm);
    if (!env) {
        int result = jvm->AttachCurrentThread(&env, nullptr);
        CHECK_EQ(result, JNI_OK) << "thread attach failed";
        struct VmDetacher {
            VmDetacher(JavaVM* vm) : mVm(vm) {}
            ~VmDetacher() { mVm->DetachCurrentThread(); }

        private:
            JavaVM* const mVm;
        };
        static thread_local VmDetacher detacher(jvm);
    }
    return env;
}
