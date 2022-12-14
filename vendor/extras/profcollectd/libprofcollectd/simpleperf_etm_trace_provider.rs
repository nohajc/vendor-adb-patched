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

//! Trace provider backed by ARM Coresight ETM, using simpleperf tool.

use anyhow::{anyhow, Result};
use std::fs::{read_dir, remove_file};
use std::path::{Path, PathBuf};
use std::time::Duration;
use trace_provider::TraceProvider;

use crate::trace_provider;

static ETM_TRACEFILE_EXTENSION: &str = "etmtrace";
static ETM_PROFILE_EXTENSION: &str = "data";

pub struct SimpleperfEtmTraceProvider {}

impl TraceProvider for SimpleperfEtmTraceProvider {
    fn get_name(&self) -> &'static str {
        "simpleperf_etm"
    }

    fn is_ready(&self) -> bool {
        simpleperf_profcollect::has_device_support()
    }

    fn trace(&self, trace_dir: &Path, tag: &str, sampling_period: &Duration, binary_filter: &str) {
        let trace_file = trace_provider::get_path(trace_dir, tag, ETM_TRACEFILE_EXTENSION);
        // Record ETM data for kernel space only when it's not filtered out by binary_filter. So we
        // can get more ETM data for user space when ETM data for kernel space isn't needed.
        let record_scope = if binary_filter.contains("kernel") {
            simpleperf_profcollect::RecordScope::BOTH
        } else {
            simpleperf_profcollect::RecordScope::USERSPACE
        };

        simpleperf_profcollect::record(&trace_file, sampling_period, binary_filter, record_scope);
    }

    fn process(&self, trace_dir: &Path, profile_dir: &Path, binary_filter: &str) -> Result<()> {
        let is_etm_extension = |file: &PathBuf| {
            file.extension()
                .and_then(|f| f.to_str())
                .filter(|ext| ext == &ETM_TRACEFILE_EXTENSION)
                .is_some()
        };

        let process_trace_file = |trace_file: PathBuf| {
            let mut profile_file = PathBuf::from(profile_dir);
            profile_file.push(
                trace_file
                    .file_name()
                    .ok_or_else(|| anyhow!("Malformed trace path: {}", trace_file.display()))?,
            );
            profile_file.set_extension(ETM_PROFILE_EXTENSION);
            simpleperf_profcollect::process(&trace_file, &profile_file, binary_filter);
            remove_file(&trace_file)?;
            Ok(())
        };

        read_dir(trace_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|e| e.is_file())
            .filter(is_etm_extension)
            .try_for_each(process_trace_file)
    }

    fn set_log_file(&self, filename: &Path) {
        simpleperf_profcollect::set_log_file(filename);
    }

    fn reset_log_file(&self) {
        simpleperf_profcollect::reset_log_file();
    }
}

impl SimpleperfEtmTraceProvider {
    pub fn supported() -> bool {
        simpleperf_profcollect::has_driver_support()
    }
}
