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

#include <compositionengine/impl/DumpHelpers.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include "DisplayHardware/HWC2.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

namespace android::compositionengine::impl {

namespace {

void dumpHwc(const OutputLayerCompositionState::Hwc& hwc, std::string& out) {
    out.append("\n      hwc: ");

    if (hwc.hwcLayer == nullptr) {
        out.append("No layer ");
    } else {
        dumpHex(out, "layer", hwc.hwcLayer->getId());
    }

    dumpVal(out, "composition", toString(hwc.hwcCompositionType), hwc.hwcCompositionType);
}

} // namespace

void OutputLayerCompositionState::dump(std::string& out) const {
    out.append("      ");
    dumpVal(out, "visibleRegion", visibleRegion);

    out.append("      ");
    dumpVal(out, "visibleNonTransparentRegion", visibleNonTransparentRegion);

    out.append("      ");
    dumpVal(out, "coveredRegion", coveredRegion);

    out.append("      ");
    dumpVal(out, "output visibleRegion", outputSpaceVisibleRegion);

    out.append("      ");
    dumpVal(out, "shadowRegion", shadowRegion);

    out.append("      ");
    dumpVal(out, "outputSpaceBlockingRegionHint", outputSpaceBlockingRegionHint);

    out.append("      ");
    dumpVal(out, "forceClientComposition", forceClientComposition);
    dumpVal(out, "clearClientTarget", clearClientTarget);
    dumpVal(out, "displayFrame", displayFrame);
    dumpVal(out, "sourceCrop", sourceCrop);
    dumpVal(out, "bufferTransform", toString(bufferTransform), bufferTransform);
    dumpVal(out, "dataspace", toString(dataspace), dataspace);
    dumpVal(out, "whitePointNits", whitePointNits);
    dumpVal(out, "dimmingRatio", dimmingRatio);
    dumpVal(out, "override buffer", overrideInfo.buffer.get());
    dumpVal(out, "override acquire fence", overrideInfo.acquireFence.get());
    dumpVal(out, "override display frame", overrideInfo.displayFrame);
    dumpVal(out, "override dataspace", toString(overrideInfo.dataspace), overrideInfo.dataspace);
    dumpVal(out, "override display space", to_string(overrideInfo.displaySpace));
    std::string damageRegionString;
    overrideInfo.damageRegion.dump(damageRegionString, "");
    dumpVal(out, "override damage region", damageRegionString);
    std::string visibleRegionString;
    overrideInfo.visibleRegion.dump(visibleRegionString, "");
    dumpVal(out, "override visible region", visibleRegionString);
    dumpVal(out, "override peekThroughLayer", overrideInfo.peekThroughLayer);
    dumpVal(out, "override disableBackgroundBlur", overrideInfo.disableBackgroundBlur);

    if (hwc) {
        dumpHwc(*hwc, out);
    }

    out.append("\n");
}

} // namespace android::compositionengine::impl
