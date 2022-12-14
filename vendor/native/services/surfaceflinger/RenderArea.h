#pragma once

#include <ui/GraphicTypes.h>
#include <ui/Transform.h>

#include <functional>

namespace android {

class DisplayDevice;

// RenderArea describes a rectangular area that layers can be rendered to.
//
// There is a logical render area and a physical render area.  When a layer is
// rendered to the render area, it is first transformed and clipped to the logical
// render area.  The transformed and clipped layer is then projected onto the
// physical render area.
class RenderArea {
public:
    using RotationFlags = ui::Transform::RotationFlags;

    enum class CaptureFill {CLEAR, OPAQUE};

    static float getCaptureFillValue(CaptureFill captureFill);

    RenderArea(uint32_t reqWidth, uint32_t reqHeight, CaptureFill captureFill,
               ui::Dataspace reqDataSpace, const Rect& displayViewport,
               RotationFlags rotation = ui::Transform::ROT_0)
          : mReqWidth(reqWidth),
            mReqHeight(reqHeight),
            mReqDataSpace(reqDataSpace),
            mCaptureFill(captureFill),
            mRotationFlags(rotation),
            mDisplayViewport(displayViewport) {}

    virtual ~RenderArea() = default;

    // Invoke drawLayers to render layers into the render area.
    virtual void render(std::function<void()> drawLayers) { drawLayers(); }

    // Returns true if the render area is secure.  A secure layer should be
    // blacked out / skipped when rendered to an insecure render area.
    virtual bool isSecure() const = 0;

    // Returns true if the otherwise disabled layer filtering should be
    // enabled when rendering to this render area.
    virtual bool needsFiltering() const = 0;

    // Returns the transform to be applied on layers to transform them into
    // the logical render area.
    virtual const ui::Transform& getTransform() const = 0;

    // Returns the size of the logical render area.  Layers are clipped to the
    // logical render area.
    virtual int getWidth() const = 0;
    virtual int getHeight() const = 0;
    virtual Rect getBounds() const = 0;

    // Returns the source crop of the render area.  The source crop defines
    // how layers are projected from the logical render area onto the physical
    // render area.  It can be larger than the logical render area.  It can
    // also be optionally rotated.
    //
    // The source crop is specified in layer space (when rendering a layer and
    // its children), or in layer-stack space (when rendering all layers visible
    // on the display).
    virtual Rect getSourceCrop() const = 0;

    // Returns the rotation of the source crop and the layers.
    RotationFlags getRotationFlags() const { return mRotationFlags; }

    // Returns the size of the physical render area.
    int getReqWidth() const { return static_cast<int>(mReqWidth); }
    int getReqHeight() const { return static_cast<int>(mReqHeight); }

    // Returns the composition data space of the render area.
    ui::Dataspace getReqDataSpace() const { return mReqDataSpace; }

    // Returns the fill color of the physical render area.  Regions not
    // covered by any rendered layer should be filled with this color.
    CaptureFill getCaptureFill() const { return mCaptureFill; }

    virtual sp<const DisplayDevice> getDisplayDevice() const = 0;

    // Returns the source display viewport.
    const Rect& getDisplayViewport() const { return mDisplayViewport; }

private:
    const uint32_t mReqWidth;
    const uint32_t mReqHeight;
    const ui::Dataspace mReqDataSpace;
    const CaptureFill mCaptureFill;
    const RotationFlags mRotationFlags;
    const Rect mDisplayViewport;
};

} // namespace android
