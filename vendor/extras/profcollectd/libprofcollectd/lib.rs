//
// Copyright (C) 2020 The Android Open Source Project
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

//! ProfCollect Binder client interface.

mod config;
mod report;
mod scheduler;
mod service;
mod simpleperf_etm_trace_provider;
mod trace_provider;

#[cfg(feature = "test")]
mod logging_trace_provider;

use anyhow::{Context, Result};
use profcollectd_aidl_interface::aidl::com::android::server::profcollect::IProfCollectd::{
    self, BnProfCollectd,
};
use profcollectd_aidl_interface::binder::{self, BinderFeatures};
use service::ProfcollectdBinderService;

const PROFCOLLECTD_SERVICE_NAME: &str = "profcollectd";

/// Initialise profcollectd service.
/// * `schedule_now` - Immediately schedule collection after service is initialised.
pub fn init_service(schedule_now: bool) -> Result<()> {
    binder::ProcessState::start_thread_pool();

    let profcollect_binder_service = ProfcollectdBinderService::new()?;
    binder::add_service(
        &PROFCOLLECTD_SERVICE_NAME,
        BnProfCollectd::new_binder(profcollect_binder_service, BinderFeatures::default())
            .as_binder(),
    )
    .context("Failed to register service.")?;

    if schedule_now {
        trace_once("boot")?;
        schedule()?;
    }

    binder::ProcessState::join_thread_pool();
    Ok(())
}

fn get_profcollectd_service() -> Result<binder::Strong<dyn IProfCollectd::IProfCollectd>> {
    binder::get_interface(&PROFCOLLECTD_SERVICE_NAME)
        .context("Failed to get profcollectd binder service, is profcollectd running?")
}

/// Schedule periodic profile collection.
pub fn schedule() -> Result<()> {
    get_profcollectd_service()?.schedule()?;
    Ok(())
}

/// Terminate periodic profile collection.
pub fn terminate() -> Result<()> {
    get_profcollectd_service()?.terminate()?;
    Ok(())
}

/// Immediately schedule a one-off trace.
pub fn trace_once(tag: &str) -> Result<()> {
    get_profcollectd_service()?.trace_once(tag)?;
    Ok(())
}

/// Process traces.
pub fn process() -> Result<()> {
    get_profcollectd_service()?.process(true)?;
    Ok(())
}

/// Process traces and report profile.
pub fn report() -> Result<String> {
    Ok(get_profcollectd_service()?.report()?)
}

/// Inits logging for Android
pub fn init_logging() {
    let min_log_level = if cfg!(feature = "test") { log::Level::Info } else { log::Level::Error };
    android_logger::init_once(
        android_logger::Config::default().with_tag("profcollectd").with_min_level(min_log_level),
    );
}
