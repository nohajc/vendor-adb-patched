/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.server.profcollect;

/** {@hide} */
interface IProfCollectd {
    void schedule();
    void terminate();
    void trace_once(@utf8InCpp String tag);
    void process(boolean blocking);
    @utf8InCpp String report();
    void copy_report_to_bb(int bb_profile_id, @utf8InCpp String report);
    void delete_report(@utf8InCpp String report);
    @utf8InCpp String get_supported_provider();
}
