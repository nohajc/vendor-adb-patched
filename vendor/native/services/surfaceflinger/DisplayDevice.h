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

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include <android/native_window.h>
#include <binder/IBinder.h>
#include <gui/LayerState.h>
#include <math/mat4.h>
#include <renderengine/RenderEngine.h>
#include <system/window.h>
#include <ui/DisplayInfo.h>
#include <ui/DisplayState.h>
#include <ui/GraphicTypes.h>
#include <ui/HdrCapabilities.h>
#include <ui/Region.h>
#include <ui/Transform.h>
#include <utils/Mutex.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

#include "DisplayHardware/DisplayIdentification.h"
#include "DisplayHardware/Hal.h"
#include "DisplayHardware/PowerAdvisor.h"
#include "RenderArea.h"
#include "Scheduler/HwcStrongTypes.h"

namespace android {

class Fence;
class HWComposer;
class IGraphicBufferProducer;
class Layer;
class SurfaceFlinger;

struct CompositionInfo;
struct DisplayDeviceCreationArgs;

namespace compositionengine {
class Display;
class DisplaySurface;
} // namespace compositionengine

class DisplayDevice : public LightRefBase<DisplayDevice> {
public:
    constexpr static float sDefaultMinLumiance = 0.0;
    constexpr static float sDefaultMaxLumiance = 500.0;

    explicit DisplayDevice(DisplayDeviceCreationArgs& args);
    virtual ~DisplayDevice();

    std::shared_ptr<compositionengine::Display> getCompositionDisplay() const {
        return mCompositionDisplay;
    }

    std::optional<DisplayConnectionType> getConnectionType() const { return mConnectionType; }

    bool isVirtual() const { return !mConnectionType; }
    bool isPrimary() const { return mIsPrimary; }

    // isSecure indicates whether this display can be trusted to display
    // secure surfaces.
    bool isSecure() const;

    int getWidth() const;
    int getHeight() const;
    ui::Size getSize() const { return {getWidth(), getHeight()}; }

    void setLayerStack(ui::LayerStack);
    void setDisplaySize(int width, int height);
    void setProjection(ui::Rotation orientation, Rect viewport, Rect frame);

    ui::Rotation getPhysicalOrientation() const { return mPhysicalOrientation; }
    ui::Rotation getOrientation() const { return mOrientation; }

    static ui::Transform::RotationFlags getPrimaryDisplayRotationFlags();

    ui::Transform::RotationFlags getTransformHint() const {
        return static_cast<ui::Transform::RotationFlags>(getTransform().getOrientation());
    }

    const ui::Transform& getTransform() const;
    const Rect& getViewport() const;
    const Rect& getFrame() const;
    const Rect& getSourceClip() const;
    bool needsFiltering() const;
    ui::LayerStack getLayerStack() const;

    const std::optional<DisplayId>& getId() const;
    const wp<IBinder>& getDisplayToken() const { return mDisplayToken; }
    int32_t getSequenceId() const { return mSequenceId; }

    const Region& getUndefinedRegion() const;

    int32_t getSupportedPerFrameMetadata() const;

    bool hasWideColorGamut() const;
    // Whether h/w composer has native support for specific HDR type.
    bool hasHDR10PlusSupport() const;
    bool hasHDR10Support() const;
    bool hasHLGSupport() const;
    bool hasDolbyVisionSupport() const;

    // The returned HdrCapabilities is the combination of HDR capabilities from
    // hardware composer and RenderEngine. When the DisplayDevice supports wide
    // color gamut, RenderEngine is able to simulate HDR support in Display P3
    // color space for both PQ and HLG HDR contents. The minimum and maximum
    // luminance will be set to sDefaultMinLumiance and sDefaultMaxLumiance
    // respectively if hardware composer doesn't return meaningful values.
    const HdrCapabilities& getHdrCapabilities() const;

    // Return true if intent is supported by the display.
    bool hasRenderIntent(ui::RenderIntent intent) const;

    const Rect& getBounds() const;
    const Rect& bounds() const { return getBounds(); }

    void setDisplayName(const std::string& displayName);
    const std::string& getDisplayName() const { return mDisplayName; }

    /* ------------------------------------------------------------------------
     * Display power mode management.
     */
    hardware::graphics::composer::hal::PowerMode getPowerMode() const;
    void setPowerMode(hardware::graphics::composer::hal::PowerMode mode);
    bool isPoweredOn() const;

    ui::Dataspace getCompositionDataSpace() const;

    /* ------------------------------------------------------------------------
     * Display active config management.
     */
    HwcConfigIndexType getActiveConfig() const;
    void setActiveConfig(HwcConfigIndexType mode);

    // release HWC resources (if any) for removable displays
    void disconnect();

    /* ------------------------------------------------------------------------
     * Debugging
     */
    uint32_t getPageFlipCount() const;
    std::string getDebugName() const;
    void dump(std::string& result) const;

private:
    const sp<SurfaceFlinger> mFlinger;
    const wp<IBinder> mDisplayToken;
    const int32_t mSequenceId;
    const std::optional<DisplayConnectionType> mConnectionType;

    const std::shared_ptr<compositionengine::Display> mCompositionDisplay;

    std::string mDisplayName;

    const ui::Rotation mPhysicalOrientation;
    ui::Rotation mOrientation = ui::ROTATION_0;

    static ui::Transform::RotationFlags sPrimaryDisplayRotationFlags;

    hardware::graphics::composer::hal::PowerMode mPowerMode =
            hardware::graphics::composer::hal::PowerMode::OFF;
    HwcConfigIndexType mActiveConfig;

    // TODO(b/74619554): Remove special cases for primary display.
    const bool mIsPrimary;
};

struct DisplayDeviceState {
    struct Physical {
        DisplayId id;
        DisplayConnectionType type;
        hardware::graphics::composer::hal::HWDisplayId hwcDisplayId;

        bool operator==(const Physical& other) const {
            return id == other.id && type == other.type && hwcDisplayId == other.hwcDisplayId;
        }
    };

    bool isVirtual() const { return !physical; }

    int32_t sequenceId = sNextSequenceId++;
    std::optional<Physical> physical;
    sp<IGraphicBufferProducer> surface;
    ui::LayerStack layerStack = ui::NO_LAYER_STACK;
    Rect viewport;
    Rect frame;
    ui::Rotation orientation = ui::ROTATION_0;
    uint32_t width = 0;
    uint32_t height = 0;
    std::string displayName;
    bool isSecure = false;

private:
    static std::atomic<int32_t> sNextSequenceId;
};

struct DisplayDeviceCreationArgs {
    // We use a constructor to ensure some of the values are set, without
    // assuming a default value.
    DisplayDeviceCreationArgs(const sp<SurfaceFlinger>&, const wp<IBinder>& displayToken,
                              std::shared_ptr<compositionengine::Display>);
    const sp<SurfaceFlinger> flinger;
    const wp<IBinder> displayToken;
    const std::shared_ptr<compositionengine::Display> compositionDisplay;

    int32_t sequenceId{0};
    std::optional<DisplayConnectionType> connectionType;
    bool isSecure{false};
    sp<ANativeWindow> nativeWindow;
    sp<compositionengine::DisplaySurface> displaySurface;
    ui::Rotation physicalOrientation{ui::ROTATION_0};
    bool hasWideColorGamut{false};
    HdrCapabilities hdrCapabilities;
    int32_t supportedPerFrameMetadata{0};
    std::unordered_map<ui::ColorMode, std::vector<ui::RenderIntent>> hwcColorModes;
    hardware::graphics::composer::hal::PowerMode initialPowerMode{
            hardware::graphics::composer::hal::PowerMode::ON};
    bool isPrimary{false};
};

class DisplayRenderArea : public RenderArea {
public:
    DisplayRenderArea(const sp<const DisplayDevice>& display,
                      RotationFlags rotation = ui::Transform::ROT_0)
          : DisplayRenderArea(display, display->getBounds(),
                              static_cast<uint32_t>(display->getWidth()),
                              static_cast<uint32_t>(display->getHeight()),
                              display->getCompositionDataSpace(), rotation) {}

    DisplayRenderArea(sp<const DisplayDevice> display, const Rect& sourceCrop, uint32_t reqWidth,
                      uint32_t reqHeight, ui::Dataspace reqDataSpace, RotationFlags rotation,
                      bool allowSecureLayers = true)
          : RenderArea(reqWidth, reqHeight, CaptureFill::OPAQUE, reqDataSpace,
                       display->getViewport(), applyDeviceOrientation(rotation, display)),
            mDisplay(std::move(display)),
            mSourceCrop(sourceCrop),
            mAllowSecureLayers(allowSecureLayers) {}

    const ui::Transform& getTransform() const override { return mTransform; }
    Rect getBounds() const override { return mDisplay->getBounds(); }
    int getHeight() const override { return mDisplay->getHeight(); }
    int getWidth() const override { return mDisplay->getWidth(); }
    bool isSecure() const override { return mAllowSecureLayers && mDisplay->isSecure(); }
    sp<const DisplayDevice> getDisplayDevice() const override { return mDisplay; }

    bool needsFiltering() const override {
        // check if the projection from the logical render area
        // to the physical render area requires filtering
        const Rect& sourceCrop = getSourceCrop();
        int width = sourceCrop.width();
        int height = sourceCrop.height();
        if (getRotationFlags() & ui::Transform::ROT_90) {
            std::swap(width, height);
        }
        return width != getReqWidth() || height != getReqHeight();
    }

    Rect getSourceCrop() const override {
        // use the projected display viewport by default.
        if (mSourceCrop.isEmpty()) {
            return mDisplay->getSourceClip();
        }

        // If there is a source crop provided then it is assumed that the device
        // was in portrait orientation. This may not logically be true, so
        // correct for the orientation error by undoing the rotation

        ui::Rotation logicalOrientation = mDisplay->getOrientation();
        if (logicalOrientation == ui::Rotation::Rotation90) {
            logicalOrientation = ui::Rotation::Rotation270;
        } else if (logicalOrientation == ui::Rotation::Rotation270) {
            logicalOrientation = ui::Rotation::Rotation90;
        }

        const auto flags = ui::Transform::toRotationFlags(logicalOrientation);
        int width = mDisplay->getSourceClip().getWidth();
        int height = mDisplay->getSourceClip().getHeight();
        ui::Transform rotation;
        rotation.set(flags, width, height);
        return rotation.transform(mSourceCrop);
    }

private:
    static RotationFlags applyDeviceOrientation(RotationFlags orientationFlag,
                                                const sp<const DisplayDevice>& device) {
        uint32_t inverseRotate90 = 0;
        uint32_t inverseReflect = 0;

        // Reverse the logical orientation.
        ui::Rotation logicalOrientation = device->getOrientation();
        if (logicalOrientation == ui::Rotation::Rotation90) {
            logicalOrientation = ui::Rotation::Rotation270;
        } else if (logicalOrientation == ui::Rotation::Rotation270) {
            logicalOrientation = ui::Rotation::Rotation90;
        }

        const ui::Rotation orientation = logicalOrientation;

        switch (orientation) {
            case ui::ROTATION_0:
                return orientationFlag;

            case ui::ROTATION_90:
                inverseRotate90 = ui::Transform::ROT_90;
                inverseReflect = ui::Transform::ROT_180;
                break;

            case ui::ROTATION_180:
                inverseReflect = ui::Transform::ROT_180;
                break;

            case ui::ROTATION_270:
                inverseRotate90 = ui::Transform::ROT_90;
                break;
        }

        const uint32_t rotate90 = orientationFlag & ui::Transform::ROT_90;
        uint32_t reflect = orientationFlag & ui::Transform::ROT_180;

        // Apply reflection for double rotation.
        if (rotate90 & inverseRotate90) {
            reflect = ~reflect & ui::Transform::ROT_180;
        }

        return static_cast<RotationFlags>((rotate90 ^ inverseRotate90) |
                                          (reflect ^ inverseReflect));
    }

    const sp<const DisplayDevice> mDisplay;
    const Rect mSourceCrop;
    const bool mAllowSecureLayers;
    const ui::Transform mTransform = ui::Transform();
};

} // namespace android
