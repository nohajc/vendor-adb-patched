//
// Copyright (C) 2021 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! This module implements safe wrappers for simpleperf etm operations required
//! by profcollect.

use std::ffi::CString;
use std::path::Path;
use std::time::Duration;

fn path_to_cstr(path: &Path) -> CString {
    CString::new(path.to_str().unwrap()).unwrap()
}

/// Returns whether the system has support for simpleperf etm.
pub fn has_support() -> bool {
    unsafe { simpleperf_profcollect_bindgen::HasSupport() }
}

/// ETM recording scope
pub enum RecordScope {
    /// Record etm data only for userspace.
    USERSPACE,
    /// Record etm data only for kernel.
    KERNEL,
    /// Record etm data for both userspace and kernel.
    BOTH,
}

/// Trigger an ETM trace event.
pub fn record(trace_file: &Path, duration: &Duration, scope: RecordScope) {
    let event_name: CString = match scope {
        RecordScope::USERSPACE => CString::new("cs-etm:u").unwrap(),
        RecordScope::KERNEL => CString::new("cs-etm:k").unwrap(),
        RecordScope::BOTH => CString::new("cs-etm").unwrap(),
    };
    let trace_file = path_to_cstr(trace_file);
    let duration = duration.as_secs_f32();

    unsafe {
        simpleperf_profcollect_bindgen::Record(event_name.as_ptr(), trace_file.as_ptr(), duration);
    }
}

/// Translate ETM trace to profile.
pub fn process(trace_path: &Path, profile_path: &Path) {
    let trace_path = path_to_cstr(trace_path);
    let profile_path = path_to_cstr(profile_path);

    unsafe {
        simpleperf_profcollect_bindgen::Inject(trace_path.as_ptr(), profile_path.as_ptr());
    }
}
