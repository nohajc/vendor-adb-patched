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

//! This module implements safe wrappers for GetServerConfigurableFlag method
//! from libflags.

use std::ffi::{CStr, CString};

/// Use the category name and flag name registered in SettingsToPropertiesMapper.java
/// to query the experiment flag value. This method will return default_value if
/// querying fails.
/// Note that for flags from Settings.Global, experiment_category_name should
/// always be global_settings.
pub fn get_server_configurable_flag<'a>(
    experiment_category_name: &str,
    experiment_flag_name: &str,
    default_value: &'a str,
) -> &'a str {
    let experiment_category_name = CString::new(experiment_category_name).unwrap();
    let experiment_flag_name = CString::new(experiment_flag_name).unwrap();
    let default_value = CString::new(default_value).unwrap();
    unsafe {
        let cstr = profcollect_libflags_bindgen::GetServerConfigurableFlag(
            experiment_category_name.as_ptr(),
            experiment_flag_name.as_ptr(),
            default_value.as_ptr(),
        );
        CStr::from_ptr(cstr).to_str().unwrap()
    }
}
