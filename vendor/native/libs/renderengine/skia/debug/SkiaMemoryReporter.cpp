/*
 * Copyright (C) 2021 The Android Open Source Project
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
#undef LOG_TAG
#define LOG_TAG "RenderEngine"

#include "SkiaMemoryReporter.h"

#include <SkString.h>
#include <android-base/stringprintf.h>
#include <log/log_main.h>

namespace android {
namespace renderengine {
namespace skia {

using base::StringAppendF;

SkiaMemoryReporter::SkiaMemoryReporter(const std::vector<ResourcePair>& resourceMap, bool itemize)
      : mResourceMap(resourceMap),
        mItemize(itemize),
        mTotalSize("bytes", 0),
        mPurgeableSize("bytes", 0) {}

const char* SkiaMemoryReporter::mapName(const char* resourceName) {
    for (auto& resource : mResourceMap) {
        if (SkStrContains(resourceName, resource.first)) {
            return resource.second;
        }
    }
    return nullptr;
}

void SkiaMemoryReporter::resetCurrentElement() {
    mCurrentElement.clear();
    mCurrentValues.clear();
    mIsCurrentValueWrapped = false;
}

void SkiaMemoryReporter::processCurrentElement() {
    // compute the top level element name using the map
    const char* resourceName = mCurrentElement.empty() ? nullptr : mapName(mCurrentElement.c_str());

    // if we don't have a resource name then we don't know how to label the
    // data and should abort.
    if (resourceName == nullptr) {
        resetCurrentElement();
        return;
    }

    // Only count elements that contain "size"; other values just provide metadata.
    auto sizeResult = mCurrentValues.find("size");
    if (sizeResult != mCurrentValues.end() && sizeResult->second.value > 0) {
        if (!mIsCurrentValueWrapped) {
            mTotalSize.value += sizeResult->second.value;
            mTotalSize.count++;
        }
    } else {
        resetCurrentElement();
        return;
    }

    // find the purgeable size if one exists
    auto purgeableResult = mCurrentValues.find("purgeable_size");
    if (!mIsCurrentValueWrapped && purgeableResult != mCurrentValues.end()) {
        mPurgeableSize.value += purgeableResult->second.value;
        mPurgeableSize.count++;
    }

    // do we store this element in the wrapped list or the skia managed list
    auto& results = mIsCurrentValueWrapped ? mWrappedResults : mResults;

    // insert a copy of the element and all of its keys. We must make a copy here instead of
    // std::move() as we will continue to use these values later in the function and again
    // when we move on to process the next element.
    results.insert({mCurrentElement, mCurrentValues});

    // insert the item into its mapped category
    auto result = results.find(resourceName);
    if (result != results.end()) {
        auto& resourceValues = result->second;
        auto totalResult = resourceValues.find(sizeResult->first);
        if (totalResult != resourceValues.end()) {
            ALOGE_IF(sizeResult->second.units != totalResult->second.units,
                     "resource units do not match so the sum of resource type (%s) will be invalid",
                     resourceName);
            totalResult->second.value += sizeResult->second.value;
            totalResult->second.count++;
        } else {
            ALOGE("an entry (%s) should not exist in the results without a size", resourceName);
        }
    } else {
        // only store the size for the top level resource
        results.insert({resourceName, {{sizeResult->first, sizeResult->second}}});
    }

    resetCurrentElement();
}

void SkiaMemoryReporter::dumpNumericValue(const char* dumpName, const char* valueName,
                                          const char* units, uint64_t value) {
    if (mCurrentElement != dumpName) {
        processCurrentElement();
        mCurrentElement = dumpName;
    }
    mCurrentValues.insert({valueName, {units, value}});
}

void SkiaMemoryReporter::dumpWrappedState(const char* dumpName, bool isWrappedObject) {
    if (mCurrentElement != dumpName) {
        processCurrentElement();
        mCurrentElement = dumpName;
    }
    mIsCurrentValueWrapped = isWrappedObject;
}

void SkiaMemoryReporter::logOutput(std::string& log, bool wrappedResources) {
    // process the current element before logging
    processCurrentElement();

    const auto& resultsMap = wrappedResources ? mWrappedResults : mResults;

    // log each individual element based on the resource map
    for (const auto& resourceCategory : mResourceMap) {
        // find the named item and print the totals
        const auto categoryItem = resultsMap.find(resourceCategory.second);
        if (categoryItem != resultsMap.end()) {
            auto result = categoryItem->second.find("size");
            if (result != categoryItem->second.end()) {
                TraceValue traceValue = convertUnits(result->second);
                const char* entry = (traceValue.count > 1) ? "entries" : "entry";
                StringAppendF(&log, "  %s: %.2f %s (%d %s)\n", categoryItem->first.c_str(),
                              traceValue.value, traceValue.units, traceValue.count, entry);
            }
            if (mItemize) {
                for (const auto& individualItem : resultsMap) {
                    // if the individual item matches the category then print all its details or
                    // in the case of wrapped resources just print the wrapped size
                    const char* categoryMatch = mapName(individualItem.first.c_str());
                    if (categoryMatch && strcmp(categoryMatch, resourceCategory.second) == 0) {
                        auto result = individualItem.second.find("size");
                        TraceValue size = convertUnits(result->second);
                        StringAppendF(&log, "    %s: size[%.2f %s]", individualItem.first.c_str(),
                                      size.value, size.units);
                        if (!wrappedResources) {
                            for (const auto& itemValues : individualItem.second) {
                                if (strcmp("size", itemValues.first) == 0) {
                                    continue;
                                }
                                TraceValue traceValue = convertUnits(itemValues.second);
                                if (traceValue.value == 0.0f) {
                                    StringAppendF(&log, " %s[%s]", itemValues.first,
                                                  traceValue.units);
                                } else {
                                    StringAppendF(&log, " %s[%.2f %s]", itemValues.first,
                                                  traceValue.value, traceValue.units);
                                }
                            }
                        }
                        StringAppendF(&log, "\n");
                    }
                }
            }
        }
    }
}

void SkiaMemoryReporter::logTotals(std::string& log) {
    // process the current element before logging
    processCurrentElement();

    TraceValue total = convertUnits(mTotalSize);
    TraceValue purgeable = convertUnits(mPurgeableSize);
    StringAppendF(&log, " %.0f bytes, %.2f %s (%.2f %s is purgeable)\n", mTotalSize.value,
                  total.value, total.units, purgeable.value, purgeable.units);
}

SkiaMemoryReporter::TraceValue SkiaMemoryReporter::convertUnits(const TraceValue& value) {
    TraceValue output(value);
    if (SkString("bytes") == SkString(output.units) && output.value >= 1024) {
        output.value = output.value / 1024.0f;
        output.units = "KB";
    }
    if (SkString("KB") == SkString(output.units) && output.value >= 1024) {
        output.value = output.value / 1024.0f;
        output.units = "MB";
    }
    return output;
}

} /* namespace skia */
} /* namespace renderengine */
} /* namespace android */
