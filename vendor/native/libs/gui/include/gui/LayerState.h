/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef ANDROID_SF_LAYER_STATE_H
#define ANDROID_SF_LAYER_STATE_H


#include <stdint.h>
#include <sys/types.h>

#include <android/native_window.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/ITransactionCompletedListener.h>
#include <math/mat4.h>

#include <android/gui/DropInputMode.h>
#include <android/gui/FocusRequest.h>

#include <gui/ISurfaceComposer.h>
#include <gui/LayerMetadata.h>
#include <gui/SurfaceControl.h>
#include <gui/WindowInfo.h>
#include <math/vec3.h>
#include <ui/BlurRegion.h>
#include <ui/GraphicTypes.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <ui/Rotation.h>
#include <ui/StretchEffect.h>
#include <ui/Transform.h>
#include <utils/Errors.h>

namespace android {

class Parcel;
class ISurfaceComposerClient;

struct client_cache_t {
    wp<IBinder> token = nullptr;
    uint64_t id;

    bool operator==(const client_cache_t& other) const { return id == other.id; }

    bool isValid() const { return token != nullptr; }
};

/*
 * Used to communicate layer information between SurfaceFlinger and its clients.
 */
struct layer_state_t {
    enum Permission {
        ACCESS_SURFACE_FLINGER = 0x1,
        ROTATE_SURFACE_FLINGER = 0x2,
        INTERNAL_SYSTEM_WINDOW = 0x4,
    };

    enum {
        eLayerHidden = 0x01,         // SURFACE_HIDDEN in SurfaceControl.java
        eLayerOpaque = 0x02,         // SURFACE_OPAQUE
        eLayerSkipScreenshot = 0x40, // SKIP_SCREENSHOT
        eLayerSecure = 0x80,         // SECURE
        // Queue up BufferStateLayer buffers instead of dropping the oldest buffer when this flag is
        // set. This blocks the client until all the buffers have been presented. If the buffers
        // have presentation timestamps, then we may drop buffers.
        eEnableBackpressure = 0x100, // ENABLE_BACKPRESSURE
    };

    enum {
        ePositionChanged = 0x00000001,
        eLayerChanged = 0x00000002,
        eSizeChanged = 0x00000004,
        eAlphaChanged = 0x00000008,
        eMatrixChanged = 0x00000010,
        eTransparentRegionChanged = 0x00000020,
        eFlagsChanged = 0x00000040,
        eLayerStackChanged = 0x00000080,
        eReleaseBufferListenerChanged = 0x00000400,
        eShadowRadiusChanged = 0x00000800,
        eLayerCreated = 0x00001000,
        eBufferCropChanged = 0x00002000,
        eRelativeLayerChanged = 0x00004000,
        eReparent = 0x00008000,
        eColorChanged = 0x00010000,
        eDestroySurface = 0x00020000,
        eTransformChanged = 0x00040000,
        eTransformToDisplayInverseChanged = 0x00080000,
        eCropChanged = 0x00100000,
        eBufferChanged = 0x00200000,
        eAcquireFenceChanged = 0x00400000,
        eDataspaceChanged = 0x00800000,
        eHdrMetadataChanged = 0x01000000,
        eSurfaceDamageRegionChanged = 0x02000000,
        eApiChanged = 0x04000000,
        eSidebandStreamChanged = 0x08000000,
        eColorTransformChanged = 0x10000000,
        eHasListenerCallbacksChanged = 0x20000000,
        eInputInfoChanged = 0x40000000,
        eCornerRadiusChanged = 0x80000000,
        eDestinationFrameChanged = 0x1'00000000,
        eCachedBufferChanged = 0x2'00000000,
        eBackgroundColorChanged = 0x4'00000000,
        eMetadataChanged = 0x8'00000000,
        eColorSpaceAgnosticChanged = 0x10'00000000,
        eFrameRateSelectionPriority = 0x20'00000000,
        eFrameRateChanged = 0x40'00000000,
        eBackgroundBlurRadiusChanged = 0x80'00000000,
        eProducerDisconnect = 0x100'00000000,
        eFixedTransformHintChanged = 0x200'00000000,
        eFrameNumberChanged = 0x400'00000000,
        eBlurRegionsChanged = 0x800'00000000,
        eAutoRefreshChanged = 0x1000'00000000,
        eStretchChanged = 0x2000'00000000,
        eTrustedOverlayChanged = 0x4000'00000000,
        eDropInputModeChanged = 0x8000'00000000,
    };

    layer_state_t();

    void merge(const layer_state_t& other);
    status_t write(Parcel& output) const;
    status_t read(const Parcel& input);
    bool hasBufferChanges() const;
    bool hasValidBuffer() const;
    void sanitize(int32_t permissions);

    struct matrix22_t {
        float dsdx{0};
        float dtdx{0};
        float dtdy{0};
        float dsdy{0};
        status_t write(Parcel& output) const;
        status_t read(const Parcel& input);
    };
    sp<IBinder> surface;
    int32_t layerId;
    uint64_t what;
    float x;
    float y;
    int32_t z;
    uint32_t w;
    uint32_t h;
    uint32_t layerStack;
    float alpha;
    uint32_t flags;
    uint32_t mask;
    uint8_t reserved;
    matrix22_t matrix;
    float cornerRadius;
    uint32_t backgroundBlurRadius;
    sp<SurfaceControl> reparentSurfaceControl;

    sp<SurfaceControl> relativeLayerSurfaceControl;

    sp<SurfaceControl> parentSurfaceControlForChild;

    half3 color;

    // non POD must be last. see write/read
    Region transparentRegion;

    uint32_t transform;
    bool transformToDisplayInverse;
    Rect crop;
    Rect orientedDisplaySpaceRect;
    sp<GraphicBuffer> buffer;
    sp<Fence> acquireFence;
    ui::Dataspace dataspace;
    HdrMetadata hdrMetadata;
    Region surfaceDamageRegion;
    int32_t api;
    sp<NativeHandle> sidebandStream;
    mat4 colorTransform;
    std::vector<BlurRegion> blurRegions;

    sp<gui::WindowInfoHandle> windowInfoHandle = new gui::WindowInfoHandle();

    client_cache_t cachedBuffer;

    LayerMetadata metadata;

    // The following refer to the alpha, and dataspace, respectively of
    // the background color layer
    float bgColorAlpha;
    ui::Dataspace bgColorDataspace;

    // A color space agnostic layer means the color of this layer can be
    // interpreted in any color space.
    bool colorSpaceAgnostic;

    std::vector<ListenerCallbacks> listeners;

    // Draws a shadow around the surface.
    float shadowRadius;

    // Priority of the layer assigned by Window Manager.
    int32_t frameRateSelectionPriority;

    // Layer frame rate and compatibility. See ANativeWindow_setFrameRate().
    float frameRate;
    int8_t frameRateCompatibility;
    int8_t changeFrameRateStrategy;

    // Set by window manager indicating the layer and all its children are
    // in a different orientation than the display. The hint suggests that
    // the graphic producers should receive a transform hint as if the
    // display was in this orientation. When the display changes to match
    // the layer orientation, the graphic producer may not need to allocate
    // a buffer of a different size. -1 means the transform hint is not set,
    // otherwise the value will be a valid ui::Rotation.
    ui::Transform::RotationFlags fixedTransformHint;

    // Used by BlastBufferQueue to forward the framenumber generated by the
    // graphics producer.
    uint64_t frameNumber;

    // Indicates that the consumer should acquire the next frame as soon as it
    // can and not wait for a frame to become available. This is only relevant
    // in shared buffer mode.
    bool autoRefresh;

    // An inherited state that indicates that this surface control and its children
    // should be trusted for input occlusion detection purposes
    bool isTrustedOverlay;

    // Stretch effect to be applied to this layer
    StretchEffect stretchEffect;

    Rect bufferCrop;
    Rect destinationFrame;

    // Listens to when the buffer is safe to be released. This is used for blast
    // layers only. The callback includes a release fence as well as the graphic
    // buffer id to identify the buffer.
    sp<ITransactionCompletedListener> releaseBufferListener;

    // Keeps track of the release callback id associated with the listener. This
    // is not sent to the server since the id can be reconstructed there. This
    // is used to remove the old callback from the client process map if it is
    // overwritten by another setBuffer call.
    ReleaseCallbackId releaseCallbackId;

    // Stores which endpoint the release information should be sent to. We don't want to send the
    // releaseCallbackId and release fence to all listeners so we store which listener the setBuffer
    // was called with.
    sp<IBinder> releaseBufferEndpoint;

    // Force inputflinger to drop all input events for the layer and its children.
    gui::DropInputMode dropInputMode;
};

struct ComposerState {
    layer_state_t state;
    status_t write(Parcel& output) const;
    status_t read(const Parcel& input);
};

struct DisplayState {
    enum {
        eSurfaceChanged = 0x01,
        eLayerStackChanged = 0x02,
        eDisplayProjectionChanged = 0x04,
        eDisplaySizeChanged = 0x08,
        eFlagsChanged = 0x10
    };

    DisplayState();
    void merge(const DisplayState& other);

    uint32_t what;
    sp<IBinder> token;
    sp<IGraphicBufferProducer> surface;
    uint32_t layerStack;
    uint32_t flags;

    // These states define how layers are projected onto the physical display.
    //
    // Layers are first clipped to `layerStackSpaceRect'.  They are then translated and
    // scaled from `layerStackSpaceRect' to `orientedDisplaySpaceRect'.  Finally, they are rotated
    // according to `orientation', `width', and `height'.
    //
    // For example, assume layerStackSpaceRect is Rect(0, 0, 200, 100), orientedDisplaySpaceRect is
    // Rect(20, 10, 420, 210), and the size of the display is WxH.  When orientation is 0, layers
    // will be scaled by a factor of 2 and translated by (20, 10). When orientation is 1, layers
    // will be additionally rotated by 90 degrees around the origin clockwise and translated by (W,
    // 0).
    ui::Rotation orientation = ui::ROTATION_0;
    Rect layerStackSpaceRect;
    Rect orientedDisplaySpaceRect;

    uint32_t width, height;

    status_t write(Parcel& output) const;
    status_t read(const Parcel& input);
};

struct InputWindowCommands {
    std::vector<gui::FocusRequest> focusRequests;
    bool syncInputWindows{false};

    // Merges the passed in commands and returns true if there were any changes.
    bool merge(const InputWindowCommands& other);
    bool empty() const;
    void clear();
    status_t write(Parcel& output) const;
    status_t read(const Parcel& input);
};

static inline int compare_type(const ComposerState& lhs, const ComposerState& rhs) {
    if (lhs.state.surface < rhs.state.surface) return -1;
    if (lhs.state.surface > rhs.state.surface) return 1;
    return 0;
}

static inline int compare_type(const DisplayState& lhs, const DisplayState& rhs) {
    return compare_type(lhs.token, rhs.token);
}

// Returns true if the frameRate is valid.
//
// @param frameRate the frame rate in Hz
// @param compatibility a ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_*
// @param changeFrameRateStrategy a ANATIVEWINDOW_CHANGE_FRAME_RATE_*
// @param functionName calling function or nullptr. Used for logging
// @param privileged whether caller has unscoped surfaceflinger access
bool ValidateFrameRate(float frameRate, int8_t compatibility, int8_t changeFrameRateStrategy,
                       const char* functionName, bool privileged = false);

struct CaptureArgs {
    const static int32_t UNSET_UID = -1;
    virtual ~CaptureArgs() = default;

    ui::PixelFormat pixelFormat{ui::PixelFormat::RGBA_8888};
    Rect sourceCrop;
    float frameScaleX{1};
    float frameScaleY{1};
    bool captureSecureLayers{false};
    int32_t uid{UNSET_UID};
    // Force capture to be in a color space. If the value is ui::Dataspace::UNKNOWN, the captured
    // result will be in the display's colorspace.
    // The display may use non-RGB dataspace (ex. displayP3) that could cause pixel data could be
    // different from SRGB (byte per color), and failed when checking colors in tests.
    // NOTE: In normal cases, we want the screen to be captured in display's colorspace.
    ui::Dataspace dataspace = ui::Dataspace::UNKNOWN;

    // The receiver of the capture can handle protected buffer. A protected buffer has
    // GRALLOC_USAGE_PROTECTED usage bit and must not be accessed unprotected behaviour.
    // Any read/write access from unprotected context will result in undefined behaviour.
    // Protected contents are typically DRM contents. This has no direct implication to the
    // secure property of the surface, which is specified by the application explicitly to avoid
    // the contents being accessed/captured by screenshot or unsecure display.
    bool allowProtected = false;

    bool grayscale = false;

    virtual status_t write(Parcel& output) const;
    virtual status_t read(const Parcel& input);
};

struct DisplayCaptureArgs : CaptureArgs {
    sp<IBinder> displayToken;
    uint32_t width{0};
    uint32_t height{0};
    bool useIdentityTransform{false};

    status_t write(Parcel& output) const override;
    status_t read(const Parcel& input) override;
};

struct LayerCaptureArgs : CaptureArgs {
    sp<IBinder> layerHandle;
    std::unordered_set<sp<IBinder>, ISurfaceComposer::SpHash<IBinder>> excludeHandles;
    bool childrenOnly{false};

    status_t write(Parcel& output) const override;
    status_t read(const Parcel& input) override;
};

}; // namespace android

#endif // ANDROID_SF_LAYER_STATE_H
