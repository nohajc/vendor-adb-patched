/*
 * Copyright (C) 2019 The Android Open Source Project
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
package android.os.storage;

/** {@hide} */
parcelable CrateMetadata {
    /**
     * To tell which uid the crate belong to.
     * <p>Because installd query all of crates in specified userId, the install may return the list
     * whose elements have the same crate id but different uid and package name.
     * It needs to tell the caller the difference between these elements.
     */
    int uid;

    /**
     * To tell which the package the crate belong to.
     * <p>Because installd query all of crates in specified uid, the install may return the list
     * whose elements have the same uid and crate id but different package name.
     * It needs to tell the caller the difference between these elements.
     */
    @utf8InCpp String packageName;

    /**
     * To tell the crate id that is the child directory/folder name in crates
     * root.
     */
    @utf8InCpp String id;
}
