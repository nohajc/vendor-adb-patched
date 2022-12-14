/*
 * Copyright (C) 2007 The Android Open Source Project
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

// tag as surfaceflinger
#define LOG_TAG "SurfaceFlinger"

#include <android/gui/IDisplayEventConnection.h>
#include <android/gui/IRegionSamplingListener.h>
#include <android/gui/ITransactionTraceListener.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/ISurfaceComposer.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerDebugInfo.h>
#include <gui/LayerState.h>
#include <private/gui/ParcelUtils.h>
#include <stdint.h>
#include <sys/types.h>
#include <system/graphics.h>
#include <ui/DisplayMode.h>
#include <ui/DisplayStatInfo.h>
#include <ui/DisplayState.h>
#include <ui/DynamicDisplayInfo.h>
#include <ui/HdrCapabilities.h>
#include <ui/StaticDisplayInfo.h>
#include <utils/Log.h>

// ---------------------------------------------------------------------------

using namespace aidl::android::hardware::graphics;

namespace android {

using gui::DisplayCaptureArgs;
using gui::IDisplayEventConnection;
using gui::IRegionSamplingListener;
using gui::IWindowInfosListener;
using gui::LayerCaptureArgs;
using ui::ColorMode;

class BpSurfaceComposer : public BpInterface<ISurfaceComposer>
{
public:
    explicit BpSurfaceComposer(const sp<IBinder>& impl)
        : BpInterface<ISurfaceComposer>(impl)
    {
    }

    virtual ~BpSurfaceComposer();

    virtual sp<ISurfaceComposerClient> createConnection()
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        remote()->transact(BnSurfaceComposer::CREATE_CONNECTION, data, &reply);
        return interface_cast<ISurfaceComposerClient>(reply.readStrongBinder());
    }

    status_t setTransactionState(const FrameTimelineInfo& frameTimelineInfo,
                                 const Vector<ComposerState>& state,
                                 const Vector<DisplayState>& displays, uint32_t flags,
                                 const sp<IBinder>& applyToken, const InputWindowCommands& commands,
                                 int64_t desiredPresentTime, bool isAutoTimestamp,
                                 const client_cache_t& uncacheBuffer, bool hasListenerCallbacks,
                                 const std::vector<ListenerCallbacks>& listenerCallbacks,
                                 uint64_t transactionId) override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());

        SAFE_PARCEL(frameTimelineInfo.write, data);

        SAFE_PARCEL(data.writeUint32, static_cast<uint32_t>(state.size()));
        for (const auto& s : state) {
            SAFE_PARCEL(s.write, data);
        }

        SAFE_PARCEL(data.writeUint32, static_cast<uint32_t>(displays.size()));
        for (const auto& d : displays) {
            SAFE_PARCEL(d.write, data);
        }

        SAFE_PARCEL(data.writeUint32, flags);
        SAFE_PARCEL(data.writeStrongBinder, applyToken);
        SAFE_PARCEL(commands.write, data);
        SAFE_PARCEL(data.writeInt64, desiredPresentTime);
        SAFE_PARCEL(data.writeBool, isAutoTimestamp);
        SAFE_PARCEL(data.writeStrongBinder, uncacheBuffer.token.promote());
        SAFE_PARCEL(data.writeUint64, uncacheBuffer.id);
        SAFE_PARCEL(data.writeBool, hasListenerCallbacks);

        SAFE_PARCEL(data.writeVectorSize, listenerCallbacks);
        for (const auto& [listener, callbackIds] : listenerCallbacks) {
            SAFE_PARCEL(data.writeStrongBinder, listener);
            SAFE_PARCEL(data.writeParcelableVector, callbackIds);
        }

        SAFE_PARCEL(data.writeUint64, transactionId);

        if (flags & ISurfaceComposer::eOneWay) {
            return remote()->transact(BnSurfaceComposer::SET_TRANSACTION_STATE,
                    data, &reply, IBinder::FLAG_ONEWAY);
        } else {
            return remote()->transact(BnSurfaceComposer::SET_TRANSACTION_STATE,
                    data, &reply);
        }
    }

    void bootFinished() override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        remote()->transact(BnSurfaceComposer::BOOT_FINISHED, data, &reply);
    }

    bool authenticateSurfaceTexture(
            const sp<IGraphicBufferProducer>& bufferProducer) const override {
        Parcel data, reply;
        int err = NO_ERROR;
        err = data.writeInterfaceToken(
                ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            ALOGE("ISurfaceComposer::authenticateSurfaceTexture: error writing "
                    "interface descriptor: %s (%d)", strerror(-err), -err);
            return false;
        }
        err = data.writeStrongBinder(IInterface::asBinder(bufferProducer));
        if (err != NO_ERROR) {
            ALOGE("ISurfaceComposer::authenticateSurfaceTexture: error writing "
                    "strong binder to parcel: %s (%d)", strerror(-err), -err);
            return false;
        }
        err = remote()->transact(BnSurfaceComposer::AUTHENTICATE_SURFACE, data,
                &reply);
        if (err != NO_ERROR) {
            ALOGE("ISurfaceComposer::authenticateSurfaceTexture: error "
                    "performing transaction: %s (%d)", strerror(-err), -err);
            return false;
        }
        int32_t result = 0;
        err = reply.readInt32(&result);
        if (err != NO_ERROR) {
            ALOGE("ISurfaceComposer::authenticateSurfaceTexture: error "
                    "retrieving result: %s (%d)", strerror(-err), -err);
            return false;
        }
        return result != 0;
    }

    status_t getSupportedFrameTimestamps(std::vector<FrameEvent>* outSupported) const override {
        if (!outSupported) {
            return UNEXPECTED_NULL;
        }
        outSupported->clear();

        Parcel data, reply;

        status_t err = data.writeInterfaceToken(
                ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            return err;
        }

        err = remote()->transact(
                BnSurfaceComposer::GET_SUPPORTED_FRAME_TIMESTAMPS,
                data, &reply);
        if (err != NO_ERROR) {
            return err;
        }

        int32_t result = 0;
        err = reply.readInt32(&result);
        if (err != NO_ERROR) {
            return err;
        }
        if (result != NO_ERROR) {
            return result;
        }

        std::vector<int32_t> supported;
        err = reply.readInt32Vector(&supported);
        if (err != NO_ERROR) {
            return err;
        }

        outSupported->reserve(supported.size());
        for (int32_t s : supported) {
            outSupported->push_back(static_cast<FrameEvent>(s));
        }
        return NO_ERROR;
    }

    sp<IDisplayEventConnection> createDisplayEventConnection(
            VsyncSource vsyncSource, EventRegistrationFlags eventRegistration) override {
        Parcel data, reply;
        sp<IDisplayEventConnection> result;
        int err = data.writeInterfaceToken(
                ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            return result;
        }
        data.writeInt32(static_cast<int32_t>(vsyncSource));
        data.writeUint32(eventRegistration.get());
        err = remote()->transact(
                BnSurfaceComposer::CREATE_DISPLAY_EVENT_CONNECTION,
                data, &reply);
        if (err != NO_ERROR) {
            ALOGE("ISurfaceComposer::createDisplayEventConnection: error performing "
                    "transaction: %s (%d)", strerror(-err), -err);
            return result;
        }
        result = interface_cast<IDisplayEventConnection>(reply.readStrongBinder());
        return result;
    }

    status_t getStaticDisplayInfo(const sp<IBinder>& display,
                                  ui::StaticDisplayInfo* info) override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        remote()->transact(BnSurfaceComposer::GET_STATIC_DISPLAY_INFO, data, &reply);
        const status_t result = reply.readInt32();
        if (result != NO_ERROR) return result;
        return reply.read(*info);
    }

    status_t getDynamicDisplayInfo(const sp<IBinder>& display,
                                   ui::DynamicDisplayInfo* info) override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        remote()->transact(BnSurfaceComposer::GET_DYNAMIC_DISPLAY_INFO, data, &reply);
        const status_t result = reply.readInt32();
        if (result != NO_ERROR) return result;
        return reply.read(*info);
    }

    status_t getDisplayNativePrimaries(const sp<IBinder>& display,
                                       ui::DisplayPrimaries& primaries) override {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("getDisplayNativePrimaries failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("getDisplayNativePrimaries failed to writeStrongBinder: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::GET_DISPLAY_NATIVE_PRIMARIES, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getDisplayNativePrimaries failed to transact: %d", result);
            return result;
        }
        result = reply.readInt32();
        if (result == NO_ERROR) {
            memcpy(&primaries, reply.readInplace(sizeof(ui::DisplayPrimaries)),
                    sizeof(ui::DisplayPrimaries));
        }
        return result;
    }

    status_t setActiveColorMode(const sp<IBinder>& display, ColorMode colorMode) override {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("setActiveColorMode failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("setActiveColorMode failed to writeStrongBinder: %d", result);
            return result;
        }
        result = data.writeInt32(static_cast<int32_t>(colorMode));
        if (result != NO_ERROR) {
            ALOGE("setActiveColorMode failed to writeInt32: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::SET_ACTIVE_COLOR_MODE, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("setActiveColorMode failed to transact: %d", result);
            return result;
        }
        return static_cast<status_t>(reply.readInt32());
    }

    status_t setBootDisplayMode(const sp<IBinder>& display,
                                ui::DisplayModeId displayModeId) override {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("setBootDisplayMode failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("setBootDisplayMode failed to writeStrongBinder: %d", result);
            return result;
        }
        result = data.writeInt32(displayModeId);
        if (result != NO_ERROR) {
            ALOGE("setBootDisplayMode failed to writeIint32: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::SET_BOOT_DISPLAY_MODE, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("setBootDisplayMode failed to transact: %d", result);
        }
        return result;
    }

    status_t clearAnimationFrameStats() override {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("clearAnimationFrameStats failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::CLEAR_ANIMATION_FRAME_STATS, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("clearAnimationFrameStats failed to transact: %d", result);
            return result;
        }
        return reply.readInt32();
    }

    status_t getAnimationFrameStats(FrameStats* outStats) const override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        remote()->transact(BnSurfaceComposer::GET_ANIMATION_FRAME_STATS, data, &reply);
        reply.read(*outStats);
        return reply.readInt32();
    }

    virtual status_t overrideHdrTypes(const sp<IBinder>& display,
                                      const std::vector<ui::Hdr>& hdrTypes) {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeStrongBinder, display);

        std::vector<int32_t> hdrTypesVector;
        for (ui::Hdr i : hdrTypes) {
            hdrTypesVector.push_back(static_cast<int32_t>(i));
        }
        SAFE_PARCEL(data.writeInt32Vector, hdrTypesVector);

        status_t result = remote()->transact(BnSurfaceComposer::OVERRIDE_HDR_TYPES, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("overrideHdrTypes failed to transact: %d", result);
            return result;
        }
        return result;
    }

    status_t onPullAtom(const int32_t atomId, std::string* pulledData, bool* success) {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeInt32, atomId);

        status_t err = remote()->transact(BnSurfaceComposer::ON_PULL_ATOM, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("onPullAtom failed to transact: %d", err);
            return err;
        }

        int32_t size = 0;
        SAFE_PARCEL(reply.readInt32, &size);
        const void* dataPtr = reply.readInplace(size);
        if (dataPtr == nullptr) {
            return UNEXPECTED_NULL;
        }
        pulledData->assign((const char*)dataPtr, size);
        SAFE_PARCEL(reply.readBool, success);
        return NO_ERROR;
    }

    status_t enableVSyncInjections(bool enable) override {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("enableVSyncInjections failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeBool(enable);
        if (result != NO_ERROR) {
            ALOGE("enableVSyncInjections failed to writeBool: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::ENABLE_VSYNC_INJECTIONS, data, &reply,
                                    IBinder::FLAG_ONEWAY);
        if (result != NO_ERROR) {
            ALOGE("enableVSyncInjections failed to transact: %d", result);
            return result;
        }
        return result;
    }

    status_t injectVSync(nsecs_t when) override {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("injectVSync failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeInt64(when);
        if (result != NO_ERROR) {
            ALOGE("injectVSync failed to writeInt64: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::INJECT_VSYNC, data, &reply,
                                    IBinder::FLAG_ONEWAY);
        if (result != NO_ERROR) {
            ALOGE("injectVSync failed to transact: %d", result);
            return result;
        }
        return result;
    }

    status_t getLayerDebugInfo(std::vector<LayerDebugInfo>* outLayers) override {
        if (!outLayers) {
            return UNEXPECTED_NULL;
        }

        Parcel data, reply;

        status_t err = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            return err;
        }

        err = remote()->transact(BnSurfaceComposer::GET_LAYER_DEBUG_INFO, data, &reply);
        if (err != NO_ERROR) {
            return err;
        }

        int32_t result = 0;
        err = reply.readInt32(&result);
        if (err != NO_ERROR) {
            return err;
        }
        if (result != NO_ERROR) {
            return result;
        }

        outLayers->clear();
        return reply.readParcelableVector(outLayers);
    }

    status_t getCompositionPreference(ui::Dataspace* defaultDataspace,
                                      ui::PixelFormat* defaultPixelFormat,
                                      ui::Dataspace* wideColorGamutDataspace,
                                      ui::PixelFormat* wideColorGamutPixelFormat) const override {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::GET_COMPOSITION_PREFERENCE, data, &reply);
        if (error != NO_ERROR) {
            return error;
        }
        error = static_cast<status_t>(reply.readInt32());
        if (error == NO_ERROR) {
            *defaultDataspace = static_cast<ui::Dataspace>(reply.readInt32());
            *defaultPixelFormat = static_cast<ui::PixelFormat>(reply.readInt32());
            *wideColorGamutDataspace = static_cast<ui::Dataspace>(reply.readInt32());
            *wideColorGamutPixelFormat = static_cast<ui::PixelFormat>(reply.readInt32());
        }
        return error;
    }

    status_t getColorManagement(bool* outGetColorManagement) const override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        remote()->transact(BnSurfaceComposer::GET_COLOR_MANAGEMENT, data, &reply);
        bool result;
        status_t err = reply.readBool(&result);
        if (err == NO_ERROR) {
            *outGetColorManagement = result;
        }
        return err;
    }

    status_t getDisplayedContentSamplingAttributes(const sp<IBinder>& display,
                                                   ui::PixelFormat* outFormat,
                                                   ui::Dataspace* outDataspace,
                                                   uint8_t* outComponentMask) const override {
        if (!outFormat || !outDataspace || !outComponentMask) return BAD_VALUE;
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);

        status_t error =
                remote()->transact(BnSurfaceComposer::GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES,
                                   data, &reply);
        if (error != NO_ERROR) {
            return error;
        }

        uint32_t value = 0;
        error = reply.readUint32(&value);
        if (error != NO_ERROR) {
            return error;
        }
        *outFormat = static_cast<ui::PixelFormat>(value);

        error = reply.readUint32(&value);
        if (error != NO_ERROR) {
            return error;
        }
        *outDataspace = static_cast<ui::Dataspace>(value);

        error = reply.readUint32(&value);
        if (error != NO_ERROR) {
            return error;
        }
        *outComponentMask = static_cast<uint8_t>(value);
        return error;
    }

    status_t setDisplayContentSamplingEnabled(const sp<IBinder>& display, bool enable,
                                              uint8_t componentMask, uint64_t maxFrames) override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        data.writeBool(enable);
        data.writeByte(static_cast<int8_t>(componentMask));
        data.writeUint64(maxFrames);
        status_t result =
                remote()->transact(BnSurfaceComposer::SET_DISPLAY_CONTENT_SAMPLING_ENABLED, data,
                                   &reply);
        return result;
    }

    status_t getDisplayedContentSample(const sp<IBinder>& display, uint64_t maxFrames,
                                       uint64_t timestamp,
                                       DisplayedFrameStats* outStats) const override {
        if (!outStats) return BAD_VALUE;

        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        data.writeUint64(maxFrames);
        data.writeUint64(timestamp);

        status_t result =
                remote()->transact(BnSurfaceComposer::GET_DISPLAYED_CONTENT_SAMPLE, data, &reply);

        if (result != NO_ERROR) {
            return result;
        }

        result = reply.readUint64(&outStats->numFrames);
        if (result != NO_ERROR) {
            return result;
        }

        result = reply.readUint64Vector(&outStats->component_0_sample);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readUint64Vector(&outStats->component_1_sample);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readUint64Vector(&outStats->component_2_sample);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readUint64Vector(&outStats->component_3_sample);
        return result;
    }

    status_t getProtectedContentSupport(bool* outSupported) const override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        status_t error =
                remote()->transact(BnSurfaceComposer::GET_PROTECTED_CONTENT_SUPPORT, data, &reply);
        if (error != NO_ERROR) {
            return error;
        }
        error = reply.readBool(outSupported);
        return error;
    }

    status_t addRegionSamplingListener(const Rect& samplingArea, const sp<IBinder>& stopLayerHandle,
                                       const sp<IRegionSamplingListener>& listener) override {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("addRegionSamplingListener: Failed to write interface token");
            return error;
        }
        error = data.write(samplingArea);
        if (error != NO_ERROR) {
            ALOGE("addRegionSamplingListener: Failed to write sampling area");
            return error;
        }
        error = data.writeStrongBinder(stopLayerHandle);
        if (error != NO_ERROR) {
            ALOGE("addRegionSamplingListener: Failed to write stop layer handle");
            return error;
        }
        error = data.writeStrongBinder(IInterface::asBinder(listener));
        if (error != NO_ERROR) {
            ALOGE("addRegionSamplingListener: Failed to write listener");
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::ADD_REGION_SAMPLING_LISTENER, data, &reply);
        if (error != NO_ERROR) {
            ALOGE("addRegionSamplingListener: Failed to transact");
        }
        return error;
    }

    status_t removeRegionSamplingListener(const sp<IRegionSamplingListener>& listener) override {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("removeRegionSamplingListener: Failed to write interface token");
            return error;
        }
        error = data.writeStrongBinder(IInterface::asBinder(listener));
        if (error != NO_ERROR) {
            ALOGE("removeRegionSamplingListener: Failed to write listener");
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::REMOVE_REGION_SAMPLING_LISTENER, data,
                                   &reply);
        if (error != NO_ERROR) {
            ALOGE("removeRegionSamplingListener: Failed to transact");
        }
        return error;
    }

    virtual status_t addFpsListener(int32_t taskId, const sp<gui::IFpsListener>& listener) {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeInt32, taskId);
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(listener));
        const status_t error =
                remote()->transact(BnSurfaceComposer::ADD_FPS_LISTENER, data, &reply);
        if (error != OK) {
            ALOGE("addFpsListener: Failed to transact");
        }
        return error;
    }

    virtual status_t removeFpsListener(const sp<gui::IFpsListener>& listener) {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(listener));

        const status_t error =
                remote()->transact(BnSurfaceComposer::REMOVE_FPS_LISTENER, data, &reply);
        if (error != OK) {
            ALOGE("removeFpsListener: Failed to transact");
        }
        return error;
    }

    virtual status_t addTunnelModeEnabledListener(
            const sp<gui::ITunnelModeEnabledListener>& listener) {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(listener));

        const status_t error =
                remote()->transact(BnSurfaceComposer::ADD_TUNNEL_MODE_ENABLED_LISTENER, data,
                                   &reply);
        if (error != NO_ERROR) {
            ALOGE("addTunnelModeEnabledListener: Failed to transact");
        }
        return error;
    }

    virtual status_t removeTunnelModeEnabledListener(
            const sp<gui::ITunnelModeEnabledListener>& listener) {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(listener));

        const status_t error =
                remote()->transact(BnSurfaceComposer::REMOVE_TUNNEL_MODE_ENABLED_LISTENER, data,
                                   &reply);
        if (error != NO_ERROR) {
            ALOGE("removeTunnelModeEnabledListener: Failed to transact");
        }
        return error;
    }

    status_t setDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                        ui::DisplayModeId defaultMode, bool allowGroupSwitching,
                                        float primaryRefreshRateMin, float primaryRefreshRateMax,
                                        float appRequestRefreshRateMin,
                                        float appRequestRefreshRateMax) override {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayModeSpecs: failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeStrongBinder(displayToken);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayModeSpecs: failed to write display token: %d", result);
            return result;
        }
        result = data.writeInt32(defaultMode);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayModeSpecs failed to write defaultMode: %d", result);
            return result;
        }
        result = data.writeBool(allowGroupSwitching);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayModeSpecs failed to write allowGroupSwitching: %d", result);
            return result;
        }
        result = data.writeFloat(primaryRefreshRateMin);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayModeSpecs failed to write primaryRefreshRateMin: %d", result);
            return result;
        }
        result = data.writeFloat(primaryRefreshRateMax);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayModeSpecs failed to write primaryRefreshRateMax: %d", result);
            return result;
        }
        result = data.writeFloat(appRequestRefreshRateMin);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayModeSpecs failed to write appRequestRefreshRateMin: %d",
                  result);
            return result;
        }
        result = data.writeFloat(appRequestRefreshRateMax);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayModeSpecs failed to write appRequestRefreshRateMax: %d",
                  result);
            return result;
        }

        result =
                remote()->transact(BnSurfaceComposer::SET_DESIRED_DISPLAY_MODE_SPECS, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayModeSpecs failed to transact: %d", result);
            return result;
        }
        return reply.readInt32();
    }

    status_t getDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                        ui::DisplayModeId* outDefaultMode,
                                        bool* outAllowGroupSwitching,
                                        float* outPrimaryRefreshRateMin,
                                        float* outPrimaryRefreshRateMax,
                                        float* outAppRequestRefreshRateMin,
                                        float* outAppRequestRefreshRateMax) override {
        if (!outDefaultMode || !outAllowGroupSwitching || !outPrimaryRefreshRateMin ||
            !outPrimaryRefreshRateMax || !outAppRequestRefreshRateMin ||
            !outAppRequestRefreshRateMax) {
            return BAD_VALUE;
        }
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayModeSpecs failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeStrongBinder(displayToken);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayModeSpecs failed to writeStrongBinder: %d", result);
            return result;
        }
        result =
                remote()->transact(BnSurfaceComposer::GET_DESIRED_DISPLAY_MODE_SPECS, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayModeSpecs failed to transact: %d", result);
            return result;
        }

        result = reply.readInt32(outDefaultMode);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayModeSpecs failed to read defaultMode: %d", result);
            return result;
        }
        if (*outDefaultMode < 0) {
            ALOGE("%s: defaultMode must be non-negative but it was %d", __func__, *outDefaultMode);
            return BAD_VALUE;
        }

        result = reply.readBool(outAllowGroupSwitching);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayModeSpecs failed to read allowGroupSwitching: %d", result);
            return result;
        }
        result = reply.readFloat(outPrimaryRefreshRateMin);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayModeSpecs failed to read primaryRefreshRateMin: %d", result);
            return result;
        }
        result = reply.readFloat(outPrimaryRefreshRateMax);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayModeSpecs failed to read primaryRefreshRateMax: %d", result);
            return result;
        }
        result = reply.readFloat(outAppRequestRefreshRateMin);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayModeSpecs failed to read appRequestRefreshRateMin: %d", result);
            return result;
        }
        result = reply.readFloat(outAppRequestRefreshRateMax);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayModeSpecs failed to read appRequestRefreshRateMax: %d", result);
            return result;
        }
        return reply.readInt32();
    }

    status_t setGlobalShadowSettings(const half4& ambientColor, const half4& spotColor,
                                     float lightPosY, float lightPosZ, float lightRadius) override {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("setGlobalShadowSettings: failed to write interface token: %d", error);
            return error;
        }

        std::vector<float> shadowConfig = {ambientColor.r, ambientColor.g, ambientColor.b,
                                           ambientColor.a, spotColor.r,    spotColor.g,
                                           spotColor.b,    spotColor.a,    lightPosY,
                                           lightPosZ,      lightRadius};

        error = data.writeFloatVector(shadowConfig);
        if (error != NO_ERROR) {
            ALOGE("setGlobalShadowSettings: failed to write shadowConfig: %d", error);
            return error;
        }

        error = remote()->transact(BnSurfaceComposer::SET_GLOBAL_SHADOW_SETTINGS, data, &reply,
                                   IBinder::FLAG_ONEWAY);
        if (error != NO_ERROR) {
            ALOGE("setGlobalShadowSettings: failed to transact: %d", error);
            return error;
        }
        return NO_ERROR;
    }

    status_t getDisplayDecorationSupport(
            const sp<IBinder>& displayToken,
            std::optional<common::DisplayDecorationSupport>* outSupport) const override {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("getDisplayDecorationSupport: failed to write interface token: %d", error);
            return error;
        }
        error = data.writeStrongBinder(displayToken);
        if (error != NO_ERROR) {
            ALOGE("getDisplayDecorationSupport: failed to write display token: %d", error);
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::GET_DISPLAY_DECORATION_SUPPORT, data, &reply);
        if (error != NO_ERROR) {
            ALOGE("getDisplayDecorationSupport: failed to transact: %d", error);
            return error;
        }
        bool support;
        error = reply.readBool(&support);
        if (error != NO_ERROR) {
            ALOGE("getDisplayDecorationSupport: failed to read support: %d", error);
            return error;
        }

        if (support) {
            int32_t format, alphaInterpretation;
            error = reply.readInt32(&format);
            if (error != NO_ERROR) {
                ALOGE("getDisplayDecorationSupport: failed to read format: %d", error);
                return error;
            }
            error = reply.readInt32(&alphaInterpretation);
            if (error != NO_ERROR) {
                ALOGE("getDisplayDecorationSupport: failed to read alphaInterpretation: %d", error);
                return error;
            }
            outSupport->emplace();
            outSupport->value().format = static_cast<common::PixelFormat>(format);
            outSupport->value().alphaInterpretation =
                    static_cast<common::AlphaInterpretation>(alphaInterpretation);
        } else {
            outSupport->reset();
        }
        return NO_ERROR;
    }

    status_t setFrameRate(const sp<IGraphicBufferProducer>& surface, float frameRate,
                          int8_t compatibility, int8_t changeFrameRateStrategy) override {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(surface));
        SAFE_PARCEL(data.writeFloat, frameRate);
        SAFE_PARCEL(data.writeByte, compatibility);
        SAFE_PARCEL(data.writeByte, changeFrameRateStrategy);

        status_t err = remote()->transact(BnSurfaceComposer::SET_FRAME_RATE, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("setFrameRate: failed to transact: %s (%d)", strerror(-err), err);
            return err;
        }

        return reply.readInt32();
    }

    status_t setFrameTimelineInfo(const sp<IGraphicBufferProducer>& surface,
                                  const FrameTimelineInfo& frameTimelineInfo) override {
        Parcel data, reply;
        status_t err = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            ALOGE("%s: failed writing interface token: %s (%d)", __func__, strerror(-err), -err);
            return err;
        }

        err = data.writeStrongBinder(IInterface::asBinder(surface));
        if (err != NO_ERROR) {
            ALOGE("%s: failed writing strong binder: %s (%d)", __func__, strerror(-err), -err);
            return err;
        }

        SAFE_PARCEL(frameTimelineInfo.write, data);

        err = remote()->transact(BnSurfaceComposer::SET_FRAME_TIMELINE_INFO, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("%s: failed to transact: %s (%d)", __func__, strerror(-err), err);
            return err;
        }

        return reply.readInt32();
    }

    status_t addTransactionTraceListener(
            const sp<gui::ITransactionTraceListener>& listener) override {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(listener));

        return remote()->transact(BnSurfaceComposer::ADD_TRANSACTION_TRACE_LISTENER, data, &reply);
    }

    /**
     * Get priority of the RenderEngine in surface flinger.
     */
    int getGPUContextPriority() override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        status_t err =
                remote()->transact(BnSurfaceComposer::GET_GPU_CONTEXT_PRIORITY, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("getGPUContextPriority failed to read data:  %s (%d)", strerror(-err), err);
            return 0;
        }
        return reply.readInt32();
    }

    status_t getMaxAcquiredBufferCount(int* buffers) const override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        status_t err =
                remote()->transact(BnSurfaceComposer::GET_MAX_ACQUIRED_BUFFER_COUNT, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("getMaxAcquiredBufferCount failed to read data:  %s (%d)", strerror(-err), err);
            return err;
        }

        return reply.readInt32(buffers);
    }

    status_t addWindowInfosListener(
            const sp<IWindowInfosListener>& windowInfosListener) const override {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(windowInfosListener));
        return remote()->transact(BnSurfaceComposer::ADD_WINDOW_INFOS_LISTENER, data, &reply);
    }

    status_t removeWindowInfosListener(
            const sp<IWindowInfosListener>& windowInfosListener) const override {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(windowInfosListener));
        return remote()->transact(BnSurfaceComposer::REMOVE_WINDOW_INFOS_LISTENER, data, &reply);
    }

    status_t setOverrideFrameRate(uid_t uid, float frameRate) override {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeUint32, uid);
        SAFE_PARCEL(data.writeFloat, frameRate);

        status_t err = remote()->transact(BnSurfaceComposer::SET_OVERRIDE_FRAME_RATE, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("setOverrideFrameRate: failed to transact %s (%d)", strerror(-err), err);
            return err;
        }

        return NO_ERROR;
    }
};

// Out-of-line virtual method definition to trigger vtable emission in this
// translation unit (see clang warning -Wweak-vtables)
BpSurfaceComposer::~BpSurfaceComposer() {}

IMPLEMENT_META_INTERFACE(SurfaceComposer, "android.ui.ISurfaceComposer");

// ----------------------------------------------------------------------

status_t BnSurfaceComposer::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    switch(code) {
        case CREATE_CONNECTION: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> b = IInterface::asBinder(createConnection());
            reply->writeStrongBinder(b);
            return NO_ERROR;
        }
        case SET_TRANSACTION_STATE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            FrameTimelineInfo frameTimelineInfo;
            SAFE_PARCEL(frameTimelineInfo.read, data);

            uint32_t count = 0;
            SAFE_PARCEL_READ_SIZE(data.readUint32, &count, data.dataSize());
            Vector<ComposerState> state;
            state.setCapacity(count);
            for (size_t i = 0; i < count; i++) {
                ComposerState s;
                SAFE_PARCEL(s.read, data);
                state.add(s);
            }

            SAFE_PARCEL_READ_SIZE(data.readUint32, &count, data.dataSize());
            DisplayState d;
            Vector<DisplayState> displays;
            displays.setCapacity(count);
            for (size_t i = 0; i < count; i++) {
                SAFE_PARCEL(d.read, data);
                displays.add(d);
            }

            uint32_t stateFlags = 0;
            SAFE_PARCEL(data.readUint32, &stateFlags);
            sp<IBinder> applyToken;
            SAFE_PARCEL(data.readStrongBinder, &applyToken);
            InputWindowCommands inputWindowCommands;
            SAFE_PARCEL(inputWindowCommands.read, data);

            int64_t desiredPresentTime = 0;
            bool isAutoTimestamp = true;
            SAFE_PARCEL(data.readInt64, &desiredPresentTime);
            SAFE_PARCEL(data.readBool, &isAutoTimestamp);

            client_cache_t uncachedBuffer;
            sp<IBinder> tmpBinder;
            SAFE_PARCEL(data.readNullableStrongBinder, &tmpBinder);
            uncachedBuffer.token = tmpBinder;
            SAFE_PARCEL(data.readUint64, &uncachedBuffer.id);

            bool hasListenerCallbacks = false;
            SAFE_PARCEL(data.readBool, &hasListenerCallbacks);

            std::vector<ListenerCallbacks> listenerCallbacks;
            int32_t listenersSize = 0;
            SAFE_PARCEL_READ_SIZE(data.readInt32, &listenersSize, data.dataSize());
            for (int32_t i = 0; i < listenersSize; i++) {
                SAFE_PARCEL(data.readStrongBinder, &tmpBinder);
                std::vector<CallbackId> callbackIds;
                SAFE_PARCEL(data.readParcelableVector, &callbackIds);
                listenerCallbacks.emplace_back(tmpBinder, callbackIds);
            }

            uint64_t transactionId = -1;
            SAFE_PARCEL(data.readUint64, &transactionId);

            return setTransactionState(frameTimelineInfo, state, displays, stateFlags, applyToken,
                                       inputWindowCommands, desiredPresentTime, isAutoTimestamp,
                                       uncachedBuffer, hasListenerCallbacks, listenerCallbacks,
                                       transactionId);
        }
        case BOOT_FINISHED: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            bootFinished();
            return NO_ERROR;
        }
        case AUTHENTICATE_SURFACE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IGraphicBufferProducer> bufferProducer =
                    interface_cast<IGraphicBufferProducer>(data.readStrongBinder());
            int32_t result = authenticateSurfaceTexture(bufferProducer) ? 1 : 0;
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case GET_SUPPORTED_FRAME_TIMESTAMPS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            std::vector<FrameEvent> supportedTimestamps;
            status_t result = getSupportedFrameTimestamps(&supportedTimestamps);
            status_t err = reply->writeInt32(result);
            if (err != NO_ERROR) {
                return err;
            }
            if (result != NO_ERROR) {
                return result;
            }

            std::vector<int32_t> supported;
            supported.reserve(supportedTimestamps.size());
            for (FrameEvent s : supportedTimestamps) {
                supported.push_back(static_cast<int32_t>(s));
            }
            return reply->writeInt32Vector(supported);
        }
        case CREATE_DISPLAY_EVENT_CONNECTION: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            auto vsyncSource = static_cast<ISurfaceComposer::VsyncSource>(data.readInt32());
            EventRegistrationFlags eventRegistration =
                    static_cast<EventRegistration>(data.readUint32());

            sp<IDisplayEventConnection> connection(
                    createDisplayEventConnection(vsyncSource, eventRegistration));
            reply->writeStrongBinder(IInterface::asBinder(connection));
            return NO_ERROR;
        }
        case GET_STATIC_DISPLAY_INFO: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            ui::StaticDisplayInfo info;
            const sp<IBinder> display = data.readStrongBinder();
            const status_t result = getStaticDisplayInfo(display, &info);
            SAFE_PARCEL(reply->writeInt32, result);
            if (result != NO_ERROR) return result;
            SAFE_PARCEL(reply->write, info);
            return NO_ERROR;
        }
        case GET_DYNAMIC_DISPLAY_INFO: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            ui::DynamicDisplayInfo info;
            const sp<IBinder> display = data.readStrongBinder();
            const status_t result = getDynamicDisplayInfo(display, &info);
            SAFE_PARCEL(reply->writeInt32, result);
            if (result != NO_ERROR) return result;
            SAFE_PARCEL(reply->write, info);
            return NO_ERROR;
        }
        case GET_DISPLAY_NATIVE_PRIMARIES: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            ui::DisplayPrimaries primaries;
            sp<IBinder> display = nullptr;

            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("getDisplayNativePrimaries failed to readStrongBinder: %d", result);
                return result;
            }

            result = getDisplayNativePrimaries(display, primaries);
            reply->writeInt32(result);
            if (result == NO_ERROR) {
                memcpy(reply->writeInplace(sizeof(ui::DisplayPrimaries)), &primaries,
                        sizeof(ui::DisplayPrimaries));
            }

            return NO_ERROR;
        }
        case SET_ACTIVE_COLOR_MODE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("getActiveColorMode failed to readStrongBinder: %d", result);
                return result;
            }
            int32_t colorModeInt = 0;
            result = data.readInt32(&colorModeInt);
            if (result != NO_ERROR) {
                ALOGE("setActiveColorMode failed to readInt32: %d", result);
                return result;
            }
            result = setActiveColorMode(display,
                    static_cast<ColorMode>(colorModeInt));
            result = reply->writeInt32(result);
            return result;
        }
        case SET_BOOT_DISPLAY_MODE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("setBootDisplayMode failed to readStrongBinder: %d", result);
                return result;
            }
            ui::DisplayModeId displayModeId;
            result = data.readInt32(&displayModeId);
            if (result != NO_ERROR) {
                ALOGE("setBootDisplayMode failed to readInt32: %d", result);
                return result;
            }
            return setBootDisplayMode(display, displayModeId);
        }
        case CLEAR_ANIMATION_FRAME_STATS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            status_t result = clearAnimationFrameStats();
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case GET_ANIMATION_FRAME_STATS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            FrameStats stats;
            status_t result = getAnimationFrameStats(&stats);
            reply->write(stats);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case ENABLE_VSYNC_INJECTIONS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            bool enable = false;
            status_t result = data.readBool(&enable);
            if (result != NO_ERROR) {
                ALOGE("enableVSyncInjections failed to readBool: %d", result);
                return result;
            }
            return enableVSyncInjections(enable);
        }
        case INJECT_VSYNC: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            int64_t when = 0;
            status_t result = data.readInt64(&when);
            if (result != NO_ERROR) {
                ALOGE("enableVSyncInjections failed to readInt64: %d", result);
                return result;
            }
            return injectVSync(when);
        }
        case GET_LAYER_DEBUG_INFO: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            std::vector<LayerDebugInfo> outLayers;
            status_t result = getLayerDebugInfo(&outLayers);
            reply->writeInt32(result);
            if (result == NO_ERROR)
            {
                result = reply->writeParcelableVector(outLayers);
            }
            return result;
        }
        case GET_COMPOSITION_PREFERENCE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            ui::Dataspace defaultDataspace;
            ui::PixelFormat defaultPixelFormat;
            ui::Dataspace wideColorGamutDataspace;
            ui::PixelFormat wideColorGamutPixelFormat;
            status_t error =
                    getCompositionPreference(&defaultDataspace, &defaultPixelFormat,
                                             &wideColorGamutDataspace, &wideColorGamutPixelFormat);
            reply->writeInt32(error);
            if (error == NO_ERROR) {
                reply->writeInt32(static_cast<int32_t>(defaultDataspace));
                reply->writeInt32(static_cast<int32_t>(defaultPixelFormat));
                reply->writeInt32(static_cast<int32_t>(wideColorGamutDataspace));
                reply->writeInt32(static_cast<int32_t>(wideColorGamutPixelFormat));
            }
            return error;
        }
        case GET_COLOR_MANAGEMENT: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            bool result;
            status_t error = getColorManagement(&result);
            if (error == NO_ERROR) {
                reply->writeBool(result);
            }
            return error;
        }
        case GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            sp<IBinder> display = data.readStrongBinder();
            ui::PixelFormat format;
            ui::Dataspace dataspace;
            uint8_t component = 0;
            auto result =
                    getDisplayedContentSamplingAttributes(display, &format, &dataspace, &component);
            if (result == NO_ERROR) {
                reply->writeUint32(static_cast<uint32_t>(format));
                reply->writeUint32(static_cast<uint32_t>(dataspace));
                reply->writeUint32(static_cast<uint32_t>(component));
            }
            return result;
        }
        case SET_DISPLAY_CONTENT_SAMPLING_ENABLED: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            sp<IBinder> display = nullptr;
            bool enable = false;
            int8_t componentMask = 0;
            uint64_t maxFrames = 0;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("setDisplayContentSamplingEnabled failure in reading Display token: %d",
                      result);
                return result;
            }

            result = data.readBool(&enable);
            if (result != NO_ERROR) {
                ALOGE("setDisplayContentSamplingEnabled failure in reading enable: %d", result);
                return result;
            }

            result = data.readByte(static_cast<int8_t*>(&componentMask));
            if (result != NO_ERROR) {
                ALOGE("setDisplayContentSamplingEnabled failure in reading component mask: %d",
                      result);
                return result;
            }

            result = data.readUint64(&maxFrames);
            if (result != NO_ERROR) {
                ALOGE("setDisplayContentSamplingEnabled failure in reading max frames: %d", result);
                return result;
            }

            return setDisplayContentSamplingEnabled(display, enable,
                                                    static_cast<uint8_t>(componentMask), maxFrames);
        }
        case GET_DISPLAYED_CONTENT_SAMPLE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            sp<IBinder> display = data.readStrongBinder();
            uint64_t maxFrames = 0;
            uint64_t timestamp = 0;

            status_t result = data.readUint64(&maxFrames);
            if (result != NO_ERROR) {
                ALOGE("getDisplayedContentSample failure in reading max frames: %d", result);
                return result;
            }

            result = data.readUint64(&timestamp);
            if (result != NO_ERROR) {
                ALOGE("getDisplayedContentSample failure in reading timestamp: %d", result);
                return result;
            }

            DisplayedFrameStats stats;
            result = getDisplayedContentSample(display, maxFrames, timestamp, &stats);
            if (result == NO_ERROR) {
                reply->writeUint64(stats.numFrames);
                reply->writeUint64Vector(stats.component_0_sample);
                reply->writeUint64Vector(stats.component_1_sample);
                reply->writeUint64Vector(stats.component_2_sample);
                reply->writeUint64Vector(stats.component_3_sample);
            }
            return result;
        }
        case GET_PROTECTED_CONTENT_SUPPORT: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            bool result;
            status_t error = getProtectedContentSupport(&result);
            if (error == NO_ERROR) {
                reply->writeBool(result);
            }
            return error;
        }
        case ADD_REGION_SAMPLING_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            Rect samplingArea;
            status_t result = data.read(samplingArea);
            if (result != NO_ERROR) {
                ALOGE("addRegionSamplingListener: Failed to read sampling area");
                return result;
            }
            sp<IBinder> stopLayerHandle;
            result = data.readNullableStrongBinder(&stopLayerHandle);
            if (result != NO_ERROR) {
                ALOGE("addRegionSamplingListener: Failed to read stop layer handle");
                return result;
            }
            sp<IRegionSamplingListener> listener;
            result = data.readNullableStrongBinder(&listener);
            if (result != NO_ERROR) {
                ALOGE("addRegionSamplingListener: Failed to read listener");
                return result;
            }
            return addRegionSamplingListener(samplingArea, stopLayerHandle, listener);
        }
        case REMOVE_REGION_SAMPLING_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IRegionSamplingListener> listener;
            status_t result = data.readNullableStrongBinder(&listener);
            if (result != NO_ERROR) {
                ALOGE("removeRegionSamplingListener: Failed to read listener");
                return result;
            }
            return removeRegionSamplingListener(listener);
        }
        case ADD_FPS_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            int32_t taskId;
            status_t result = data.readInt32(&taskId);
            if (result != NO_ERROR) {
                ALOGE("addFpsListener: Failed to read layer handle");
                return result;
            }
            sp<gui::IFpsListener> listener;
            result = data.readNullableStrongBinder(&listener);
            if (result != NO_ERROR) {
                ALOGE("addFpsListener: Failed to read listener");
                return result;
            }
            return addFpsListener(taskId, listener);
        }
        case REMOVE_FPS_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<gui::IFpsListener> listener;
            status_t result = data.readNullableStrongBinder(&listener);
            if (result != NO_ERROR) {
                ALOGE("removeFpsListener: Failed to read listener");
                return result;
            }
            return removeFpsListener(listener);
        }
        case ADD_TUNNEL_MODE_ENABLED_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<gui::ITunnelModeEnabledListener> listener;
            status_t result = data.readNullableStrongBinder(&listener);
            if (result != NO_ERROR) {
                ALOGE("addTunnelModeEnabledListener: Failed to read listener");
                return result;
            }
            return addTunnelModeEnabledListener(listener);
        }
        case REMOVE_TUNNEL_MODE_ENABLED_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<gui::ITunnelModeEnabledListener> listener;
            status_t result = data.readNullableStrongBinder(&listener);
            if (result != NO_ERROR) {
                ALOGE("removeTunnelModeEnabledListener: Failed to read listener");
                return result;
            }
            return removeTunnelModeEnabledListener(listener);
        }
        case SET_DESIRED_DISPLAY_MODE_SPECS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> displayToken = data.readStrongBinder();
            ui::DisplayModeId defaultMode;
            status_t result = data.readInt32(&defaultMode);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayModeSpecs: failed to read defaultMode: %d", result);
                return result;
            }
            if (defaultMode < 0) {
                ALOGE("%s: defaultMode must be non-negative but it was %d", __func__, defaultMode);
                return BAD_VALUE;
            }
            bool allowGroupSwitching;
            result = data.readBool(&allowGroupSwitching);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayModeSpecs: failed to read allowGroupSwitching: %d", result);
                return result;
            }
            float primaryRefreshRateMin;
            result = data.readFloat(&primaryRefreshRateMin);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayModeSpecs: failed to read primaryRefreshRateMin: %d",
                      result);
                return result;
            }
            float primaryRefreshRateMax;
            result = data.readFloat(&primaryRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayModeSpecs: failed to read primaryRefreshRateMax: %d",
                      result);
                return result;
            }
            float appRequestRefreshRateMin;
            result = data.readFloat(&appRequestRefreshRateMin);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayModeSpecs: failed to read appRequestRefreshRateMin: %d",
                      result);
                return result;
            }
            float appRequestRefreshRateMax;
            result = data.readFloat(&appRequestRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayModeSpecs: failed to read appRequestRefreshRateMax: %d",
                      result);
                return result;
            }
            result = setDesiredDisplayModeSpecs(displayToken, defaultMode, allowGroupSwitching,
                                                primaryRefreshRateMin, primaryRefreshRateMax,
                                                appRequestRefreshRateMin, appRequestRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayModeSpecs: failed to call setDesiredDisplayModeSpecs: "
                      "%d",
                      result);
                return result;
            }
            reply->writeInt32(result);
            return result;
        }
        case GET_DESIRED_DISPLAY_MODE_SPECS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> displayToken = data.readStrongBinder();
            ui::DisplayModeId defaultMode;
            bool allowGroupSwitching;
            float primaryRefreshRateMin;
            float primaryRefreshRateMax;
            float appRequestRefreshRateMin;
            float appRequestRefreshRateMax;

            status_t result =
                    getDesiredDisplayModeSpecs(displayToken, &defaultMode, &allowGroupSwitching,
                                               &primaryRefreshRateMin, &primaryRefreshRateMax,
                                               &appRequestRefreshRateMin,
                                               &appRequestRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayModeSpecs: failed to get getDesiredDisplayModeSpecs: "
                      "%d",
                      result);
                return result;
            }

            result = reply->writeInt32(defaultMode);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayModeSpecs: failed to write defaultMode: %d", result);
                return result;
            }
            result = reply->writeBool(allowGroupSwitching);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayModeSpecs: failed to write allowGroupSwitching: %d",
                      result);
                return result;
            }
            result = reply->writeFloat(primaryRefreshRateMin);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayModeSpecs: failed to write primaryRefreshRateMin: %d",
                      result);
                return result;
            }
            result = reply->writeFloat(primaryRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayModeSpecs: failed to write primaryRefreshRateMax: %d",
                      result);
                return result;
            }
            result = reply->writeFloat(appRequestRefreshRateMin);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayModeSpecs: failed to write appRequestRefreshRateMin: %d",
                      result);
                return result;
            }
            result = reply->writeFloat(appRequestRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayModeSpecs: failed to write appRequestRefreshRateMax: %d",
                      result);
                return result;
            }
            reply->writeInt32(result);
            return result;
        }
        case SET_GLOBAL_SHADOW_SETTINGS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            std::vector<float> shadowConfig;
            status_t error = data.readFloatVector(&shadowConfig);
            if (error != NO_ERROR || shadowConfig.size() != 11) {
                ALOGE("setGlobalShadowSettings: failed to read shadowConfig: %d", error);
                return error;
            }

            half4 ambientColor = {shadowConfig[0], shadowConfig[1], shadowConfig[2],
                                  shadowConfig[3]};
            half4 spotColor = {shadowConfig[4], shadowConfig[5], shadowConfig[6], shadowConfig[7]};
            float lightPosY = shadowConfig[8];
            float lightPosZ = shadowConfig[9];
            float lightRadius = shadowConfig[10];
            return setGlobalShadowSettings(ambientColor, spotColor, lightPosY, lightPosZ,
                                           lightRadius);
        }
        case GET_DISPLAY_DECORATION_SUPPORT: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> displayToken;
            SAFE_PARCEL(data.readNullableStrongBinder, &displayToken);
            std::optional<common::DisplayDecorationSupport> support;
            auto error = getDisplayDecorationSupport(displayToken, &support);
            if (error != NO_ERROR) {
                ALOGE("getDisplayDecorationSupport failed with error %d", error);
                return error;
            }
            reply->writeBool(support.has_value());
            if (support) {
                reply->writeInt32(static_cast<int32_t>(support.value().format));
                reply->writeInt32(static_cast<int32_t>(support.value().alphaInterpretation));
            }
            return error;
        }
        case SET_FRAME_RATE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> binder;
            SAFE_PARCEL(data.readStrongBinder, &binder);

            sp<IGraphicBufferProducer> surface = interface_cast<IGraphicBufferProducer>(binder);
            if (!surface) {
                ALOGE("setFrameRate: failed to cast to IGraphicBufferProducer");
                return BAD_VALUE;
            }
            float frameRate;
            SAFE_PARCEL(data.readFloat, &frameRate);

            int8_t compatibility;
            SAFE_PARCEL(data.readByte, &compatibility);

            int8_t changeFrameRateStrategy;
            SAFE_PARCEL(data.readByte, &changeFrameRateStrategy);

            status_t result =
                    setFrameRate(surface, frameRate, compatibility, changeFrameRateStrategy);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case SET_FRAME_TIMELINE_INFO: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> binder;
            status_t err = data.readStrongBinder(&binder);
            if (err != NO_ERROR) {
                ALOGE("setFrameTimelineInfo: failed to read strong binder: %s (%d)", strerror(-err),
                      -err);
                return err;
            }
            sp<IGraphicBufferProducer> surface = interface_cast<IGraphicBufferProducer>(binder);
            if (!surface) {
                ALOGE("setFrameTimelineInfo: failed to cast to IGraphicBufferProducer: %s (%d)",
                      strerror(-err), -err);
                return err;
            }

            FrameTimelineInfo frameTimelineInfo;
            SAFE_PARCEL(frameTimelineInfo.read, data);

            status_t result = setFrameTimelineInfo(surface, frameTimelineInfo);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case ADD_TRANSACTION_TRACE_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<gui::ITransactionTraceListener> listener;
            SAFE_PARCEL(data.readStrongBinder, &listener);

            return addTransactionTraceListener(listener);
        }
        case GET_GPU_CONTEXT_PRIORITY: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            int priority = getGPUContextPriority();
            SAFE_PARCEL(reply->writeInt32, priority);
            return NO_ERROR;
        }
        case GET_MAX_ACQUIRED_BUFFER_COUNT: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            int buffers = 0;
            int err = getMaxAcquiredBufferCount(&buffers);
            if (err != NO_ERROR) {
                return err;
            }
            SAFE_PARCEL(reply->writeInt32, buffers);
            return NO_ERROR;
        }
        case OVERRIDE_HDR_TYPES: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            SAFE_PARCEL(data.readStrongBinder, &display);

            std::vector<int32_t> hdrTypes;
            SAFE_PARCEL(data.readInt32Vector, &hdrTypes);

            std::vector<ui::Hdr> hdrTypesVector;
            for (int i : hdrTypes) {
                hdrTypesVector.push_back(static_cast<ui::Hdr>(i));
            }
            return overrideHdrTypes(display, hdrTypesVector);
        }
        case ON_PULL_ATOM: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            int32_t atomId = 0;
            SAFE_PARCEL(data.readInt32, &atomId);

            std::string pulledData;
            bool success;
            status_t err = onPullAtom(atomId, &pulledData, &success);
            SAFE_PARCEL(reply->writeByteArray, pulledData.size(),
                        reinterpret_cast<const uint8_t*>(pulledData.data()));
            SAFE_PARCEL(reply->writeBool, success);
            return err;
        }
        case ADD_WINDOW_INFOS_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IWindowInfosListener> listener;
            SAFE_PARCEL(data.readStrongBinder, &listener);

            return addWindowInfosListener(listener);
        }
        case REMOVE_WINDOW_INFOS_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IWindowInfosListener> listener;
            SAFE_PARCEL(data.readStrongBinder, &listener);

            return removeWindowInfosListener(listener);
        }
        case SET_OVERRIDE_FRAME_RATE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            uid_t uid;
            SAFE_PARCEL(data.readUint32, &uid);

            float frameRate;
            SAFE_PARCEL(data.readFloat, &frameRate);

            return setOverrideFrameRate(uid, frameRate);
        }
        default: {
            return BBinder::onTransact(code, data, reply, flags);
        }
    }
}

} // namespace android
