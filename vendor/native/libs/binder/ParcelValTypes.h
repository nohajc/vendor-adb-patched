/*
 * Copyright (C) 2008 The Android Open Source Project
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

namespace android {
namespace binder {

// Keep in sync with frameworks/base/core/java/android/os/Parcel.java.
enum {
    VAL_NULL = -1,
    VAL_STRING = 0,
    VAL_INTEGER = 1,
    VAL_MAP = 2,
    VAL_BUNDLE = 3,
    VAL_PARCELABLE = 4,
    VAL_SHORT = 5,
    VAL_LONG = 6,
    VAL_FLOAT = 7,
    VAL_DOUBLE = 8,
    VAL_BOOLEAN = 9,
    VAL_CHARSEQUENCE = 10,
    VAL_LIST = 11,
    VAL_SPARSEARRAY = 12,
    VAL_BYTEARRAY = 13,
    VAL_STRINGARRAY = 14,
    VAL_IBINDER = 15,
    VAL_PARCELABLEARRAY = 16,
    VAL_OBJECTARRAY = 17,
    VAL_INTARRAY = 18,
    VAL_LONGARRAY = 19,
    VAL_BYTE = 20,
    VAL_SERIALIZABLE = 21,
    VAL_SPARSEBOOLEANARRAY = 22,
    VAL_BOOLEANARRAY = 23,
    VAL_CHARSEQUENCEARRAY = 24,
    VAL_PERSISTABLEBUNDLE = 25,
    VAL_SIZE = 26,
    VAL_SIZEF = 27,
    VAL_DOUBLEARRAY = 28,
    VAL_CHAR = 29,
    VAL_SHORTARRAY = 30,
    VAL_CHARARRAY = 31,
    VAL_FLOATARRAY = 32,
};

} // namespace binder
} // namespace android
