/*
 * Copyright (C) 2005 The Android Open Source Project
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

#include <binder/Binder.h>

#include <assert.h>

namespace android {

// ----------------------------------------------------------------------

class IInterface : public virtual RefBase
{
public:
            IInterface();
            static sp<IBinder>  asBinder(const IInterface*);
            static sp<IBinder>  asBinder(const sp<IInterface>&);

protected:
    virtual                     ~IInterface();
    virtual IBinder*            onAsBinder() = 0;
};

// ----------------------------------------------------------------------

/**
 * If this is a local object and the descriptor matches, this will return the
 * actual local object which is implementing the interface. Otherwise, this will
 * return a proxy to the interface without checking the interface descriptor.
 * This means that subsequent calls may fail with BAD_TYPE.
 */
template<typename INTERFACE>
inline sp<INTERFACE> interface_cast(const sp<IBinder>& obj)
{
    return INTERFACE::asInterface(obj);
}

/**
 * This is the same as interface_cast, except that it always checks to make sure
 * the descriptor matches, and if it doesn't match, it will return nullptr.
 */
template<typename INTERFACE>
inline sp<INTERFACE> checked_interface_cast(const sp<IBinder>& obj)
{
    if (obj->getInterfaceDescriptor() != INTERFACE::descriptor) {
        return nullptr;
    }

    return interface_cast<INTERFACE>(obj);
}

// ----------------------------------------------------------------------

template<typename INTERFACE>
class BnInterface : public INTERFACE, public BBinder
{
public:
    virtual sp<IInterface>      queryLocalInterface(const String16& _descriptor);
    virtual const String16&     getInterfaceDescriptor() const;

protected:
    typedef INTERFACE           BaseInterface;
    virtual IBinder*            onAsBinder();
};

// ----------------------------------------------------------------------

template<typename INTERFACE>
class BpInterface : public INTERFACE, public BpRefBase
{
public:
    explicit                    BpInterface(const sp<IBinder>& remote);

protected:
    typedef INTERFACE           BaseInterface;
    virtual IBinder*            onAsBinder();
};

// ----------------------------------------------------------------------

#define DECLARE_META_INTERFACE(INTERFACE)                               \
public:                                                                 \
    static const ::android::String16 descriptor;                        \
    static ::android::sp<I##INTERFACE> asInterface(                     \
            const ::android::sp<::android::IBinder>& obj);              \
    virtual const ::android::String16& getInterfaceDescriptor() const;  \
    I##INTERFACE();                                                     \
    virtual ~I##INTERFACE();                                            \
    static bool setDefaultImpl(std::unique_ptr<I##INTERFACE> impl);     \
    static const std::unique_ptr<I##INTERFACE>& getDefaultImpl();       \
private:                                                                \
    static std::unique_ptr<I##INTERFACE> default_impl;                  \
public:                                                                 \


#define __IINTF_CONCAT(x, y) (x ## y)

#ifndef DO_NOT_CHECK_MANUAL_BINDER_INTERFACES

#define IMPLEMENT_META_INTERFACE(INTERFACE, NAME)                       \
    static_assert(internal::allowedManualInterface(NAME),               \
                  "b/64223827: Manually written binder interfaces are " \
                  "considered error prone and frequently have bugs. "   \
                  "The preferred way to add interfaces is to define "   \
                  "an .aidl file to auto-generate the interface. If "   \
                  "an interface must be manually written, add its "     \
                  "name to the whitelist.");                            \
    DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE(INTERFACE, NAME)    \

#else

#define IMPLEMENT_META_INTERFACE(INTERFACE, NAME)                       \
    DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE(INTERFACE, NAME)    \

#endif

#define DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE(INTERFACE, NAME)\
    const ::android::StaticString16                                     \
        I##INTERFACE##_descriptor_static_str16(__IINTF_CONCAT(u, NAME));\
    const ::android::String16 I##INTERFACE::descriptor(                 \
        I##INTERFACE##_descriptor_static_str16);                        \
    const ::android::String16&                                          \
            I##INTERFACE::getInterfaceDescriptor() const {              \
        return I##INTERFACE::descriptor;                                \
    }                                                                   \
    ::android::sp<I##INTERFACE> I##INTERFACE::asInterface(              \
            const ::android::sp<::android::IBinder>& obj)               \
    {                                                                   \
        ::android::sp<I##INTERFACE> intr;                               \
        if (obj != nullptr) {                                           \
            intr = ::android::sp<I##INTERFACE>::cast(                   \
                obj->queryLocalInterface(I##INTERFACE::descriptor));    \
            if (intr == nullptr) {                                      \
                intr = ::android::sp<Bp##INTERFACE>::make(obj);         \
            }                                                           \
        }                                                               \
        return intr;                                                    \
    }                                                                   \
    std::unique_ptr<I##INTERFACE> I##INTERFACE::default_impl;           \
    bool I##INTERFACE::setDefaultImpl(std::unique_ptr<I##INTERFACE> impl)\
    {                                                                   \
        /* Only one user of this interface can use this function     */ \
        /* at a time. This is a heuristic to detect if two different */ \
        /* users in the same process use this function.              */ \
        assert(!I##INTERFACE::default_impl);                            \
        if (impl) {                                                     \
            I##INTERFACE::default_impl = std::move(impl);               \
            return true;                                                \
        }                                                               \
        return false;                                                   \
    }                                                                   \
    const std::unique_ptr<I##INTERFACE>& I##INTERFACE::getDefaultImpl() \
    {                                                                   \
        return I##INTERFACE::default_impl;                              \
    }                                                                   \
    I##INTERFACE::I##INTERFACE() { }                                    \
    I##INTERFACE::~I##INTERFACE() { }                                   \


#define CHECK_INTERFACE(interface, data, reply)                         \
    do {                                                                \
      if (!(data).checkInterface(this)) { return PERMISSION_DENIED; }   \
    } while (false)                                                     \


// ----------------------------------------------------------------------
// No user-serviceable parts after this...

template<typename INTERFACE>
inline sp<IInterface> BnInterface<INTERFACE>::queryLocalInterface(
        const String16& _descriptor)
{
    if (_descriptor == INTERFACE::descriptor) return sp<IInterface>::fromExisting(this);
    return nullptr;
}

template<typename INTERFACE>
inline const String16& BnInterface<INTERFACE>::getInterfaceDescriptor() const
{
    return INTERFACE::getInterfaceDescriptor();
}

template<typename INTERFACE>
IBinder* BnInterface<INTERFACE>::onAsBinder()
{
    return this;
}

template<typename INTERFACE>
inline BpInterface<INTERFACE>::BpInterface(const sp<IBinder>& remote)
    : BpRefBase(remote)
{
}

template<typename INTERFACE>
inline IBinder* BpInterface<INTERFACE>::onAsBinder()
{
    return remote();
}

// ----------------------------------------------------------------------

namespace internal {
constexpr const char* const kManualInterfaces[] = {
  "android.app.IActivityManager",
  "android.app.IUidObserver",
  "android.drm.IDrm",
  "android.dvr.IVsyncCallback",
  "android.dvr.IVsyncService",
  "android.gfx.tests.ICallback",
  "android.gfx.tests.IIPCTest",
  "android.gfx.tests.ISafeInterfaceTest",
  "android.graphicsenv.IGpuService",
  "android.gui.DisplayEventConnection",
  "android.gui.IConsumerListener",
  "android.gui.IGraphicBufferConsumer",
  "android.gui.IRegionSamplingListener",
  "android.gui.ITransactionComposerListener",
  "android.gui.SensorEventConnection",
  "android.gui.SensorServer",
  "android.hardware.ICamera",
  "android.hardware.ICameraClient",
  "android.hardware.ICameraRecordingProxy",
  "android.hardware.ICameraRecordingProxyListener",
  "android.hardware.ICrypto",
  "android.hardware.IOMXObserver",
  "android.hardware.ISoundTrigger",
  "android.hardware.ISoundTriggerClient",
  "android.hardware.ISoundTriggerHwService",
  "android.hardware.IStreamListener",
  "android.hardware.IStreamSource",
  "android.input.IInputFlinger",
  "android.input.ISetInputWindowsListener",
  "android.media.IAudioFlinger",
  "android.media.IAudioFlingerClient",
  "android.media.IAudioPolicyService",
  "android.media.IAudioPolicyServiceClient",
  "android.media.IAudioService",
  "android.media.IAudioTrack",
  "android.media.IDataSource",
  "android.media.IDrmClient",
  "android.media.IEffect",
  "android.media.IEffectClient",
  "android.media.IMediaCodecList",
  "android.media.IMediaDrmService",
  "android.media.IMediaExtractor",
  "android.media.IMediaExtractorService",
  "android.media.IMediaHTTPConnection",
  "android.media.IMediaHTTPService",
  "android.media.IMediaLogService",
  "android.media.IMediaMetadataRetriever",
  "android.media.IMediaMetricsService",
  "android.media.IMediaPlayer",
  "android.media.IMediaPlayerClient",
  "android.media.IMediaPlayerService",
  "android.media.IMediaRecorder",
  "android.media.IMediaRecorderClient",
  "android.media.IMediaResourceMonitor",
  "android.media.IMediaSource",
  "android.media.IRemoteDisplay",
  "android.media.IRemoteDisplayClient",
  "android.media.IResourceManagerClient",
  "android.media.IResourceManagerService",
  "android.os.IComplexTypeInterface",
  "android.os.IPermissionController",
  "android.os.IPingResponder",
  "android.os.IPowerManager",
  "android.os.IProcessInfoService",
  "android.os.ISchedulingPolicyService",
  "android.os.IStringConstants",
  "android.os.storage.IObbActionListener",
  "android.os.storage.IStorageEventListener",
  "android.os.storage.IStorageManager",
  "android.os.storage.IStorageShutdownObserver",
  "android.service.vr.IPersistentVrStateCallbacks",
  "android.service.vr.IVrManager",
  "android.service.vr.IVrStateCallbacks",
  "android.ui.ISurfaceComposer",
  "android.ui.ISurfaceComposerClient",
  "android.utils.IMemory",
  "android.utils.IMemoryHeap",
  "com.android.car.procfsinspector.IProcfsInspector",
  "com.android.internal.app.IAppOpsCallback",
  "com.android.internal.app.IAppOpsService",
  "com.android.internal.app.IBatteryStats",
  "com.android.internal.os.IResultReceiver",
  "com.android.internal.os.IShellCallback",
  "drm.IDrmManagerService",
  "drm.IDrmServiceListener",
  "IAAudioClient",
  "IAAudioService",
  "VtsFuzzer",
  nullptr,
};

constexpr const char* const kDownstreamManualInterfaces[] = {
  // Add downstream interfaces here.
  nullptr,
};

constexpr bool equals(const char* a, const char* b) {
  if (*a != *b) return false;
  if (*a == '\0') return true;
  return equals(a + 1, b + 1);
}

constexpr bool inList(const char* a, const char* const* whitelist) {
  if (*whitelist == nullptr) return false;
  if (equals(a, *whitelist)) return true;
  return inList(a, whitelist + 1);
}

constexpr bool allowedManualInterface(const char* name) {
  return inList(name, kManualInterfaces) ||
         inList(name, kDownstreamManualInterfaces);
}

} // namespace internal
} // namespace android
