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

//! This module implements safe wrappers for GetProperty and SetProperty from libbase.

pub use ffi::{GetProperty, SetProperty};

/// Safe wrappers for the GetProperty and SetProperty methods from libbase.
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("properties.hpp");

        /// Returns the current value of the system property `key`,
        /// or `default_value` if the property is empty or doesn't exist.
        fn GetProperty(key: &str, default_value: &str) -> String;

        /// Sets the system property `key` to `value`.
        fn SetProperty(key: &str, value: &str);
    }
}
