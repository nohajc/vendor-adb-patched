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

#pragma once

#include <SkTraceMemoryDump.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace android {
namespace renderengine {
namespace skia {

// Mapping of resource substrings (1st element) that if found within a trace "dumpName"
// should be mapped to the category name (2nd element). All char* used in a resourcePair
// are expected to have a lifetime longer than the SkiaMemoryReporter in which they are used.
typedef std::pair<const char*, const char*> ResourcePair;

/*
 * Utility class for logging the CPU/GPU usage of Skia caches in a format that is specific
 * to RenderEngine.  HWUI has a similar logging class, but the data collected and the way
 * it is formatted and reported on are intended to be unique to each use case.
 */
class SkiaMemoryReporter : public SkTraceMemoryDump {
public:
    /**
     * Creates the reporter class that can be populated by various Skia entry points, like
     * SkGraphics and GrContext, as well as format and log the results.
     * @param resourceMap An array of values that maps a Skia dumpName into a user defined category.
     *                    The first vector entry that matches the dumpName is used for the mapping.
     * @param itemize if true when logging the categories the individual elements will be printed
     *                directly after the category details are printed.  Otherwise, only the category
     *                totals will be printed.
     */
    SkiaMemoryReporter(const std::vector<ResourcePair>& resourceMap, bool itemize);
    ~SkiaMemoryReporter() override {}

    void logOutput(std::string& log, bool wrappedResources = false);
    void logTotals(std::string& log);

    void dumpNumericValue(const char* dumpName, const char* valueName, const char* units,
                          uint64_t value) override;

    void dumpStringValue(const char* dumpName, const char* valueName, const char* value) override {
        // for convenience we just store this in the same format as numerical values
        dumpNumericValue(dumpName, valueName, value, 0);
    }
    void dumpWrappedState(const char* dumpName, bool isWrappedObject) override;

    LevelOfDetail getRequestedDetails() const override {
        return SkTraceMemoryDump::kLight_LevelOfDetail;
    }

    bool shouldDumpWrappedObjects() const override { return true; }
    void setMemoryBacking(const char*, const char*, const char*) override {}
    void setDiscardableMemoryBacking(const char*, const SkDiscardableMemory&) override {}

private:
    struct TraceValue {
        TraceValue(const char* units, uint64_t value) : units(units), value(value), count(1) {}
        TraceValue(const TraceValue& v) : units(v.units), value(v.value), count(v.count) {}

        const char* units;
        float value;
        int count;
    };

    const char* mapName(const char* resourceName);
    void processCurrentElement();
    void resetCurrentElement();
    TraceValue convertUnits(const TraceValue& value);

    const std::vector<ResourcePair>& mResourceMap;
    const bool mItemize;

    // variables storing the size of all non-wrapped elements being dumped
    TraceValue mTotalSize;
    TraceValue mPurgeableSize;

    // variables storing information on the current node being dumped
    std::string mCurrentElement;
    std::unordered_map<const char*, TraceValue> mCurrentValues;
    bool mIsCurrentValueWrapped = false;

    // variable that stores the final format of the data after the individual elements are processed
    std::unordered_map<std::string, std::unordered_map<const char*, TraceValue>> mResults;
    std::unordered_map<std::string, std::unordered_map<const char*, TraceValue>> mWrappedResults;
};

} /* namespace skia */
} /* namespace renderengine */
} /* namespace android */