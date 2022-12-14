/*
 * Copyright (C) 2018 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

// #define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "ContainerLayer"

#include "ContainerLayer.h"

namespace android {

ContainerLayer::ContainerLayer(const LayerCreationArgs& args) : Layer(args) {}

ContainerLayer::~ContainerLayer() = default;

bool ContainerLayer::isVisible() const {
    return false;
}

sp<Layer> ContainerLayer::createClone() {
    sp<ContainerLayer> layer = mFlinger->getFactory().createContainerLayer(
            LayerCreationArgs(mFlinger.get(), nullptr, mName + " (Mirror)", 0, 0, 0,
                              LayerMetadata()));
    layer->setInitialValuesForClone(this);
    return layer;
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
