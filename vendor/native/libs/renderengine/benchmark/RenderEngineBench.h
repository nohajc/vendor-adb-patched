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

#include <ui/GraphicBuffer.h>

using namespace android;

/**
 * Utilities for running benchmarks.
 */
namespace renderenginebench {
/**
 * Parse RenderEngineBench-specific flags from the command line.
 *
 * --save Save the output buffer to a file to verify that it drew as
 *  expected.
 */
void parseFlags(int argc, char** argv);

/**
 * Parse flags for '--help'
 */
void parseFlagsForHelp(int argc, char** argv);

/**
 * Whether to save the drawing result to a file.
 *
 * True if --save was used on the command line.
 */
bool save();

/**
 * Decode the image at 'path' into 'buffer'.
 *
 * Currently only used for debugging. The image will be scaled to fit the
 * buffer if necessary.
 *
 * This assumes the buffer matches ANDROID_BITMAP_FORMAT_RGBA_8888.
 *
 * @param path Relative to the directory holding the executable.
 */
void decode(const char* path, const sp<GraphicBuffer>& buffer);

/**
 * Encode the buffer to a jpeg.
 *
 * This assumes the buffer matches ANDROID_BITMAP_FORMAT_RGBA_8888.
 *
 * @param path Relative to the directory holding the executable.
 */
void encodeToJpeg(const char* path, const sp<GraphicBuffer>& buffer);
} // namespace renderenginebench
