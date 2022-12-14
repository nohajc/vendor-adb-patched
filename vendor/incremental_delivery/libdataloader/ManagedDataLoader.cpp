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
#define LOG_TAG "dataloader-manageddataloader"

#include "ManagedDataLoader.h"

#include <android-base/logging.h>

#include "JNIHelpers.h"

namespace android::dataloader {

namespace {

struct JniIds {
    jclass dataLoaderParams;
    jmethodID dataLoaderParamsConstruct;

    jclass fileSystemConnector;
    jmethodID fileSystemConnectorConstruct;

    jmethodID dataLoaderServiceOnCreateDataLoader;

    jmethodID dataLoaderOnCreate;
    jmethodID dataLoaderOnPrepareImage;

    jclass installationFile;
    jmethodID installationFileCtor;

    jclass arrayList;
    jmethodID arrayListCtor;
    jmethodID arrayListAdd;

    JniIds(JNIEnv* env) {
        dataLoaderParams = (jclass)env->NewGlobalRef(
                FindClassOrDie(env, "android/content/pm/DataLoaderParams"));
        dataLoaderParamsConstruct =
                GetMethodIDOrDie(env, dataLoaderParams, "<init>",
                                 "(Landroid/content/pm/DataLoaderParamsParcel;)V");

        fileSystemConnector = (jclass)env->NewGlobalRef(
                FindClassOrDie(env,
                               "android/service/dataloader/DataLoaderService$FileSystemConnector"));
        fileSystemConnectorConstruct = GetMethodIDOrDie(env, fileSystemConnector, "<init>", "(J)V");

        auto dataLoaderService =
                FindClassOrDie(env, "android/service/dataloader/DataLoaderService");
        dataLoaderServiceOnCreateDataLoader =
                GetMethodIDOrDie(env, dataLoaderService, "onCreateDataLoader",
                                 "(Landroid/content/pm/DataLoaderParams;)Landroid/service/"
                                 "dataloader/DataLoaderService$DataLoader;");

        auto dataLoader =
                FindClassOrDie(env, "android/service/dataloader/DataLoaderService$DataLoader");
        dataLoaderOnCreate =
                GetMethodIDOrDie(env, dataLoader, "onCreate",
                                 "(Landroid/content/pm/DataLoaderParams;Landroid/service/"
                                 "dataloader/DataLoaderService$FileSystemConnector;)Z");
        dataLoaderOnPrepareImage =
                GetMethodIDOrDie(env, dataLoader, "onPrepareImage",
                                 "(Ljava/util/Collection;Ljava/util/Collection;)Z");

        arrayList = (jclass)env->NewGlobalRef(FindClassOrDie(env, "java/util/ArrayList"));
        arrayListCtor = GetMethodIDOrDie(env, arrayList, "<init>", "(I)V");
        arrayListAdd = GetMethodIDOrDie(env, arrayList, "add", "(Ljava/lang/Object;)Z");

        installationFile = (jclass)env->NewGlobalRef(
                FindClassOrDie(env, "android/content/pm/InstallationFile"));
        installationFileCtor =
                GetMethodIDOrDie(env, installationFile, "<init>", "(ILjava/lang/String;J[B[B)V");
    }
};

const JniIds& jniIds(JNIEnv* env) {
    static const JniIds ids(env);
    return ids;
}

} // namespace

ManagedDataLoader::ManagedDataLoader(JavaVM* jvm, jobject dataLoader)
      : mJvm(jvm), mDataLoader(dataLoader) {
    CHECK(mJvm);

    LegacyDataLoader::onStart = [](auto) -> bool { return true; };
    LegacyDataLoader::onStop = [](auto) {};
    LegacyDataLoader::onDestroy = [](LegacyDataLoader* self) {
        auto me = static_cast<ManagedDataLoader*>(self);
        me->onDestroy();
        delete me;
    };
    LegacyDataLoader::onPrepareImage = [](auto* self, const auto addedFiles[],
                                          int addedFilesCount) -> bool {
        return static_cast<ManagedDataLoader*>(self)->onPrepareImage(
                DataLoaderInstallationFiles(addedFiles, addedFilesCount));
    };
    LegacyDataLoader::onPendingReads = [](auto, auto, auto) {};
    LegacyDataLoader::onPageReads = [](auto, auto, auto) {};
}

LegacyDataLoader* ManagedDataLoader::create(JavaVM* jvm,
                                            android::dataloader::FilesystemConnectorPtr ifs,
                                            android::dataloader::StatusListenerPtr listener,
                                            android::dataloader::ServiceConnectorPtr service,
                                            android::dataloader::ServiceParamsPtr params) {
    JNIEnv* env = GetJNIEnvironment(jvm);
    const auto& jni = jniIds(env);

    jobject dlp = env->NewObject(jni.dataLoaderParams, jni.dataLoaderParamsConstruct, params);
    jobject ifsc =
            env->NewObject(jni.fileSystemConnector, jni.fileSystemConnectorConstruct, (jlong)ifs);

    auto dataLoader = env->CallObjectMethod(service, jni.dataLoaderServiceOnCreateDataLoader, dlp);
    if (!dataLoader) {
        LOG(ERROR) << "Failed to create Java DataLoader.";
        return nullptr;
    }
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    if (!env->CallBooleanMethod(dataLoader, jni.dataLoaderOnCreate, dlp, ifsc)) {
        return nullptr;
    }

    return new ManagedDataLoader(jvm, env->NewGlobalRef(dataLoader));
}

void ManagedDataLoader::onDestroy() {
    CHECK(mDataLoader);

    JNIEnv* env = GetJNIEnvironment(mJvm);

    env->DeleteGlobalRef(mDataLoader);
    mDataLoader = nullptr;
}

static jobject toJavaArrayList(JNIEnv* env, const JniIds& jni,
                               const DataLoaderInstallationFiles& files) {
    jobject arrayList =
            env->NewObject(jni.arrayList, jni.arrayListCtor, static_cast<jint>(files.size()));
    for (const auto& file : files) {
        const auto location(file.location);
        const auto size(file.size);

        jstring name = env->NewStringUTF(file.name);
        jbyteArray metadata = env->NewByteArray(file.metadata.size);
        if (metadata != nullptr) {
            env->SetByteArrayRegion(metadata, 0, file.metadata.size,
                                    (const jbyte*)file.metadata.data);
        }

        jobject jfile = env->NewObject(jni.installationFile, jni.installationFileCtor, location,
                                       name, size, metadata, nullptr);
        env->CallBooleanMethod(arrayList, jni.arrayListAdd, jfile);
    }
    return arrayList;
}

bool ManagedDataLoader::onPrepareImage(DataLoaderInstallationFiles addedFiles) {
    CHECK(mDataLoader);

    auto env = GetOrAttachJNIEnvironment(mJvm);
    const auto& jni = jniIds(env);

    jobject jaddedFiles = toJavaArrayList(env, jni, addedFiles);
    return env->CallBooleanMethod(mDataLoader, jni.dataLoaderOnPrepareImage, jaddedFiles, nullptr);
}

ManagedDataLoaderFactory::ManagedDataLoaderFactory() {
    ::DataLoaderFactory::onCreate =
            [](::DataLoaderFactory* self, const ::DataLoaderParams* ndkParams,
               ::DataLoaderFilesystemConnectorPtr fsConnector,
               ::DataLoaderStatusListenerPtr statusListener, ::DataLoaderServiceVmPtr vm,
               ::DataLoaderServiceConnectorPtr serviceConnector,
               ::DataLoaderServiceParamsPtr serviceParams) -> ::DataLoader* {
        return reinterpret_cast<::DataLoader*>(
                ManagedDataLoader::create(vm, static_cast<FilesystemConnector*>(fsConnector),
                                          static_cast<StatusListener*>(statusListener),
                                          serviceConnector, serviceParams));
    };
}

} // namespace android::dataloader
