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

#include <ftl/enum.h>

#include <compositionengine/impl/DumpHelpers.h>
#include <compositionengine/impl/OutputCompositionState.h>

namespace android::compositionengine::impl {

void OutputCompositionState::dump(std::string& out) const {
    out.append("   ");
    dumpVal(out, "isEnabled", isEnabled);
    dumpVal(out, "isSecure", isSecure);
    dumpVal(out, "usesDeviceComposition", usesDeviceComposition);

    out.append("\n   ");
    dumpVal(out, "usesClientComposition", usesClientComposition);
    dumpVal(out, "flipClientTarget", flipClientTarget);
    dumpVal(out, "reusedClientComposition", reusedClientComposition);

    out.append("\n   ");
    dumpVal(out, "layerFilter", layerFilter);
    out.append("\n   ");
    dumpVal(out, "transform", transform);

    out.append("   "); // ui::Transform::dump appends EOL.
    dumpVal(out, "layerStackSpace", to_string(layerStackSpace));
    out.append("\n   ");
    dumpVal(out, "framebufferSpace", to_string(framebufferSpace));
    out.append("\n   ");
    dumpVal(out, "orientedDisplaySpace", to_string(orientedDisplaySpace));
    out.append("\n   ");
    dumpVal(out, "displaySpace", to_string(displaySpace));
    out.append("\n   ");
    dumpVal(out, "needsFiltering", needsFiltering);

    out.append("\n   ");
    dumpVal(out, "colorMode", toString(colorMode), colorMode);
    dumpVal(out, "renderIntent", toString(renderIntent), renderIntent);
    dumpVal(out, "dataspace", toString(dataspace), dataspace);
    dumpVal(out, "targetDataspace", toString(targetDataspace), targetDataspace);

    out.append("\n   ");
    dumpVal(out, "colorTransformMatrix", colorTransformMatrix);

    out.append("\n   ");
    dumpVal(out, "displayBrightnessNits", displayBrightnessNits);
    dumpVal(out, "sdrWhitePointNits", sdrWhitePointNits);
    dumpVal(out, "clientTargetBrightness", clientTargetBrightness);
    dumpVal(out, "displayBrightness", displayBrightness);

    out.append("\n   ");
    dumpVal(out, "compositionStrategyPredictionState", ftl::enum_string(strategyPrediction));

    out.append("\n   ");
    dumpVal(out, "treate170mAsSrgb", treat170mAsSrgb);

    out += '\n';
}

} // namespace android::compositionengine::impl
