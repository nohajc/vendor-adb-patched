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

#define DEBUG false  // STOPSHIP if true
#define LOG_TAG "StatsAidl"

#define VLOG(...) \
    if (DEBUG) ALOGD(__VA_ARGS__);

#include "StatsAidl.h"

#include <Counter.h>
#include <log/log.h>
#include <stats_annotations.h>
#include <stats_event.h>
#include <statslog.h>

#include <unordered_map>

namespace {
    static const char* g_AtomErrorMetricName =
        "statsd_errors.value_report_vendor_atom_errors_count";
}

namespace aidl {
namespace android {
namespace frameworks {
namespace stats {

using ::android::expresslog::Counter;

template <typename E>
constexpr typename std::underlying_type<E>::type to_underlying(E e) noexcept {
    return static_cast<typename std::underlying_type<E>::type>(e);
}

StatsHal::StatsHal() {
}

bool write_annotation(AStatsEvent* event, const Annotation& annotation) {
    switch (annotation.value.getTag()) {
        case AnnotationValue::boolValue: {
            AStatsEvent_addBoolAnnotation(event, to_underlying(annotation.annotationId),
                                          annotation.value.get<AnnotationValue::boolValue>());
            break;
        }
        case AnnotationValue::intValue: {
            AStatsEvent_addInt32Annotation(event, to_underlying(annotation.annotationId),
                                           annotation.value.get<AnnotationValue::intValue>());
            break;
        }
        default: {
            return false;
        }
    }
    return true;
}

bool write_atom_annotations(AStatsEvent* event,
                            const std::vector<std::optional<Annotation>>& annotations) {
    for (const auto& atomAnnotation : annotations) {
        if (!atomAnnotation) {
            return false;
        }
        if (!write_annotation(event, *atomAnnotation)) {
            return false;
        }
    }
    return true;
}

bool write_field_annotations(AStatsEvent* event, const std::vector<Annotation>& annotations) {
    for (const auto& fieldAnnotation : annotations) {
        if (!write_annotation(event, fieldAnnotation)) {
            return false;
        }
    }
    return true;
}

ndk::ScopedAStatus StatsHal::reportVendorAtom(const VendorAtom& vendorAtom) {
    if (vendorAtom.atomId < 100000 || vendorAtom.atomId >= 200000) {
        ALOGE("Atom ID %ld is not a valid vendor atom ID", (long)vendorAtom.atomId);
        Counter::logIncrement(g_AtomErrorMetricName);
        return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(
                -1, "Not a valid vendor atom ID");
    }
    if (vendorAtom.reverseDomainName.length() > 50) {
        ALOGE("Vendor atom reverse domain name %s is too long.",
              vendorAtom.reverseDomainName.c_str());
        Counter::logIncrement(g_AtomErrorMetricName);
        return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(
                -1, "Vendor atom reverse domain name is too long");
    }
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, vendorAtom.atomId);

    if (vendorAtom.atomAnnotations) {
        if (!write_atom_annotations(event, *vendorAtom.atomAnnotations)) {
            AStatsEvent_release(event);
            ALOGE("Atom ID %ld has incompatible atom level annotation", (long)vendorAtom.atomId);
            Counter::logIncrement(g_AtomErrorMetricName);
            return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(
                    -1, "invalid atom annotation");
        }
    }

    // populate map for quickier access for VendorAtomValue associated annotations by value index
    std::unordered_map<int, int> fieldIndexToAnnotationSetMap;
    if (vendorAtom.valuesAnnotations) {
        const std::vector<std::optional<AnnotationSet>>& valuesAnnotations =
                *vendorAtom.valuesAnnotations;
        for (int i = 0; i < valuesAnnotations.size(); i++) {
            if (valuesAnnotations[i]) {
                fieldIndexToAnnotationSetMap[valuesAnnotations[i]->valueIndex] = i;
            }
        }
    }

    AStatsEvent_writeString(event, vendorAtom.reverseDomainName.c_str());
    size_t atomValueIdx = 0;
    for (const auto& atomValue : vendorAtom.values) {
        switch (atomValue.getTag()) {
            case VendorAtomValue::intValue:
                AStatsEvent_writeInt32(event, atomValue.get<VendorAtomValue::intValue>());
                break;
            case VendorAtomValue::longValue:
                AStatsEvent_writeInt64(event, atomValue.get<VendorAtomValue::longValue>());
                break;
            case VendorAtomValue::floatValue:
                AStatsEvent_writeFloat(event, atomValue.get<VendorAtomValue::floatValue>());
                break;
            case VendorAtomValue::stringValue:
                AStatsEvent_writeString(event,
                                        atomValue.get<VendorAtomValue::stringValue>().c_str());
                break;
            case VendorAtomValue::boolValue:
                AStatsEvent_writeBool(event, atomValue.get<VendorAtomValue::boolValue>());
                break;
            case VendorAtomValue::repeatedIntValue: {
                const std::optional<std::vector<int>>& repeatedIntValue =
                        atomValue.get<VendorAtomValue::repeatedIntValue>();
                if (!repeatedIntValue) {
                    AStatsEvent_writeInt32Array(event, {}, 0);
                    break;
                }
                AStatsEvent_writeInt32Array(event, repeatedIntValue->data(),
                                            repeatedIntValue->size());
                break;
            }
            case VendorAtomValue::repeatedLongValue: {
                const std::optional<std::vector<int64_t>>& repeatedLongValue =
                        atomValue.get<VendorAtomValue::repeatedLongValue>();
                if (!repeatedLongValue) {
                    AStatsEvent_writeInt64Array(event, {}, 0);
                    break;
                }
                AStatsEvent_writeInt64Array(event, repeatedLongValue->data(),
                                            repeatedLongValue->size());
                break;
            }
            case VendorAtomValue::repeatedFloatValue: {
                const std::optional<std::vector<float>>& repeatedFloatValue =
                        atomValue.get<VendorAtomValue::repeatedFloatValue>();
                if (!repeatedFloatValue) {
                    AStatsEvent_writeFloatArray(event, {}, 0);
                    break;
                }
                AStatsEvent_writeFloatArray(event, repeatedFloatValue->data(),
                                            repeatedFloatValue->size());
                break;
            }
            case VendorAtomValue::repeatedStringValue: {
                const std::optional<std::vector<std::optional<std::string>>>& repeatedStringValue =
                        atomValue.get<VendorAtomValue::repeatedStringValue>();
                if (!repeatedStringValue) {
                    AStatsEvent_writeStringArray(event, {}, 0);
                    break;
                }
                const std::vector<std::optional<std::string>>& repeatedStringVector =
                        *repeatedStringValue;
                const char* cStringArray[repeatedStringVector.size()];

                for (int i = 0; i < repeatedStringVector.size(); ++i) {
                    cStringArray[i] = repeatedStringVector[i].has_value()
                                              ? repeatedStringVector[i]->c_str()
                                              : "";
                }

                AStatsEvent_writeStringArray(event, cStringArray, repeatedStringVector.size());
                break;
            }
            case VendorAtomValue::repeatedBoolValue: {
                const std::optional<std::vector<bool>>& repeatedBoolValue =
                        atomValue.get<VendorAtomValue::repeatedBoolValue>();
                if (!repeatedBoolValue) {
                    AStatsEvent_writeBoolArray(event, {}, 0);
                    break;
                }
                const std::vector<bool>& repeatedBoolVector = *repeatedBoolValue;
                bool boolArray[repeatedBoolValue->size()];

                for (int i = 0; i < repeatedBoolVector.size(); ++i) {
                    boolArray[i] = repeatedBoolVector[i];
                }

                AStatsEvent_writeBoolArray(event, boolArray, repeatedBoolVector.size());
                break;
            }
            case VendorAtomValue::byteArrayValue: {
                const std::optional<std::vector<uint8_t>>& byteArrayValue =
                        atomValue.get<VendorAtomValue::byteArrayValue>();
                if (!byteArrayValue) {
                    AStatsEvent_writeByteArray(event, {}, 0);
                    break;
                }
                AStatsEvent_writeByteArray(event, byteArrayValue->data(), byteArrayValue->size());
                break;
            }
            default: {
                AStatsEvent_release(event);
                ALOGE("Atom ID %ld has invalid atomValue.getTag", (long)vendorAtom.atomId);
                Counter::logIncrement(g_AtomErrorMetricName);
                return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(
                        -1, "invalid atomValue.getTag");
                break;
            }
        }

        const auto& valueAnnotationIndex = fieldIndexToAnnotationSetMap.find(atomValueIdx);
        if (valueAnnotationIndex != fieldIndexToAnnotationSetMap.end()) {
            const std::vector<Annotation>& fieldAnnotations =
                    (*vendorAtom.valuesAnnotations)[valueAnnotationIndex->second]->annotations;
            VLOG("Atom ID %ld has %ld annotations for field #%ld", (long)vendorAtom.atomId,
                 (long)fieldAnnotations.size(), (long)atomValueIdx + 2);
            if (!write_field_annotations(event, fieldAnnotations)) {
                AStatsEvent_release(event);
                ALOGE("Atom ID %ld has incompatible field level annotation for field #%ld",
                      (long)vendorAtom.atomId, (long)atomValueIdx + 2);
                Counter::logIncrement(g_AtomErrorMetricName);
                return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(
                        -1, "invalid atom field annotation");
            }
        }
        atomValueIdx++;
    }
    AStatsEvent_build(event);
    const int ret = AStatsEvent_write(event);
    AStatsEvent_release(event);
    if (ret <= 0) {
        ALOGE("Error writing Atom ID %ld. Result: %d", (long)vendorAtom.atomId, ret);
        Counter::logIncrement(g_AtomErrorMetricName);
    }
    return ret <= 0 ? ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(ret,
                                                                              "report atom failed")
                    : ndk::ScopedAStatus::ok();
}

}  // namespace stats
}  // namespace frameworks
}  // namespace android
}  // namespace aidl
