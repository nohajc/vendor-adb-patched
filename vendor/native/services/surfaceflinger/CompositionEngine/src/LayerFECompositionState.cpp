/*
 * Copyright 2019 The Android Open Source Project
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

#include <android-base/stringprintf.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/impl/DumpHelpers.h>

namespace android::compositionengine {

namespace {

using android::compositionengine::impl::dumpVal;

void dumpVal(std::string& out, const char* name, half4 value) {
    using android::base::StringAppendF;
    StringAppendF(&out, "%s=[%f %f %f] ", name, static_cast<float>(value.r),
                  static_cast<float>(value.g), static_cast<float>(value.b));
}

} // namespace

std::string GenericLayerMetadataEntry::dumpAsString() const {
    using android::base::StringAppendF;
    std::string out;

    out.append("GenericLayerMetadataEntry{mandatory: ");
    StringAppendF(&out, "%d", mandatory);
    out.append(" value: ");
    for (uint8_t byte : value) {
        StringAppendF(&out, "0x08%" PRIx8 " ", byte);
    }
    out.append("]}");
    return out;
}

LayerFECompositionState::~LayerFECompositionState() = default;

void LayerFECompositionState::dump(std::string& out) const {
    out.append("      ");
    dumpVal(out, "isSecure", isSecure);
    dumpVal(out, "geomUsesSourceCrop", geomUsesSourceCrop);
    dumpVal(out, "geomBufferUsesDisplayInverseTransform", geomBufferUsesDisplayInverseTransform);
    dumpVal(out, "geomLayerTransform", geomLayerTransform);

    out.append("\n      ");
    dumpVal(out, "geomBufferSize", geomBufferSize);
    dumpVal(out, "geomContentCrop", geomContentCrop);
    dumpVal(out, "geomCrop", geomCrop);
    dumpVal(out, "geomBufferTransform", geomBufferTransform);

    out.append("\n      ");
    dumpVal(out, "transparentRegionHint", transparentRegionHint);

    out.append("      ");
    dumpVal(out, "geomLayerBounds", geomLayerBounds);

    out.append("      ");
    dumpVal(out, "shadowRadius", shadowRadius);

    out.append("\n      ");
    dumpVal(out, "blend", toString(blendMode), blendMode);
    dumpVal(out, "alpha", alpha);
    dumpVal(out, "backgroundBlurRadius", backgroundBlurRadius);
    if (stretchEffect.hasEffect()) {
        dumpVal(out, "stretchEffect", stretchEffect);
    }

    if (!blurRegions.empty()) {
        out.append("\n      blurRegions {");
        for (const auto& region : blurRegions) {
            out.append("\n           ");
            base::StringAppendF(&out,
                                "{radius=%du, cornerRadii=[%f, %f, %f, %f], alpha=%f, rect=[%d, "
                                "%d, %d, %d]",
                                region.blurRadius, region.cornerRadiusTL, region.cornerRadiusTR,
                                region.cornerRadiusBL, region.cornerRadiusBR, region.alpha,
                                region.left, region.top, region.right, region.bottom);
        }
        out.append("\n      }\n      ");
    }

    if (!metadata.empty()) {
        out.append("\n      metadata {");
        for (const auto& [key, entry] : metadata) {
            out.append("\n           ");
            out.append(key);
            out.append("=");
            out.append(entry.dumpAsString());
        }
        out.append("\n      }\n      ");
    }

    dumpVal(out, "composition type", toString(compositionType), compositionType);

    out.append("\n      buffer: ");
    dumpVal(out, "slot", bufferSlot);
    dumpVal(out, "buffer", buffer.get());

    out.append("\n      ");
    dumpVal(out, "sideband stream", sidebandStream.get());

    out.append("\n      ");
    dumpVal(out, "color", color);

    out.append("\n      ");
    dumpVal(out, "isOpaque", isOpaque);
    dumpVal(out, "hasProtectedContent", hasProtectedContent);
    dumpVal(out, "isColorspaceAgnostic", isColorspaceAgnostic);
    dumpVal(out, "dataspace", toString(dataspace), dataspace);
    dumpVal(out, "hdr metadata types", hdrMetadata.validTypes);
    dumpVal(out, "colorTransform", colorTransform);

    out.append("\n");
}

} // namespace android::compositionengine
