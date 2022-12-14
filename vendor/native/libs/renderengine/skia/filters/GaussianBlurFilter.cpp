/*
 * Copyright 2021 The Android Open Source Project
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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "GaussianBlurFilter.h"
#include <SkCanvas.h>
#include <SkData.h>
#include <SkPaint.h>
#include <SkRRect.h>
#include <SkRuntimeEffect.h>
#include <SkImageFilters.h>
#include <SkSize.h>
#include <SkString.h>
#include <SkSurface.h>
#include <log/log.h>
#include <utils/Trace.h>

namespace android {
namespace renderengine {
namespace skia {

// This constant approximates the scaling done in the software path's
// "high quality" mode, in SkBlurMask::Blur() (1 / sqrt(3)).
static const float BLUR_SIGMA_SCALE = 0.57735f;

GaussianBlurFilter::GaussianBlurFilter(): BlurFilter(/* maxCrossFadeRadius= */ 0.0f) {}

sk_sp<SkImage> GaussianBlurFilter::generate(GrRecordingContext* context, const uint32_t blurRadius,
                                            const sk_sp<SkImage> input, const SkRect& blurRect)
    const {
    // Create blur surface with the bit depth and colorspace of the original surface
    SkImageInfo scaledInfo = input->imageInfo().makeWH(std::ceil(blurRect.width() * kInputScale),
                                                       std::ceil(blurRect.height() * kInputScale));
    sk_sp<SkSurface> surface = SkSurface::MakeRenderTarget(context, SkBudgeted::kNo, scaledInfo);

    SkPaint paint;
    paint.setBlendMode(SkBlendMode::kSrc);
    paint.setImageFilter(SkImageFilters::Blur(
                blurRadius * kInputScale * BLUR_SIGMA_SCALE,
                blurRadius * kInputScale * BLUR_SIGMA_SCALE,
                SkTileMode::kClamp, nullptr));

    surface->getCanvas()->drawImageRect(
            input,
            blurRect,
            SkRect::MakeWH(scaledInfo.width(), scaledInfo.height()),
            SkSamplingOptions{SkFilterMode::kLinear, SkMipmapMode::kNone},
            &paint,
            SkCanvas::SrcRectConstraint::kFast_SrcRectConstraint);
    return surface->makeImageSnapshot();
}

} // namespace skia
} // namespace renderengine
} // namespace android
