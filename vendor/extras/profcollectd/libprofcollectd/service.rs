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

//! ProfCollect Binder service implementation.

use anyhow::{anyhow, bail, Context, Error, Result};
use binder::public_api::Result as BinderResult;
use binder::Status;
use profcollectd_aidl_interface::aidl::com::android::server::profcollect::IProfCollectd::IProfCollectd;
use std::ffi::CString;
use std::fs::{copy, create_dir, read_to_string, remove_dir_all, remove_file, write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

use crate::config::{
    Config, BETTERBUG_CACHE_DIR_PREFIX, BETTERBUG_CACHE_DIR_SUFFIX, CONFIG_FILE,
    PROFILE_OUTPUT_DIR, REPORT_OUTPUT_DIR, TRACE_OUTPUT_DIR,
};
use crate::report::pack_report;
use crate::scheduler::Scheduler;

fn err_to_binder_status(msg: Error) -> Status {
    let msg = format!("{:#?}", msg);
    let msg = CString::new(msg).expect("Failed to convert to CString");
    Status::new_service_specific_error(1, Some(&msg))
}

pub struct ProfcollectdBinderService {
    lock: Mutex<Lock>,
}

struct Lock {
    config: Config,
    scheduler: Scheduler,
}

impl binder::Interface for ProfcollectdBinderService {}

impl IProfCollectd for ProfcollectdBinderService {
    fn schedule(&self) -> BinderResult<()> {
        let lock = &mut *self.lock();
        lock.scheduler
            .schedule_periodic(&lock.config)
            .context("Failed to schedule collection.")
            .map_err(err_to_binder_status)
    }
    fn terminate(&self) -> BinderResult<()> {
        self.lock()
            .scheduler
            .terminate_periodic()
            .context("Failed to terminate collection.")
            .map_err(err_to_binder_status)
    }
    fn trace_once(&self, tag: &str) -> BinderResult<()> {
        let lock = &mut *self.lock();
        lock.scheduler
            .one_shot(&lock.config, tag)
            .context("Failed to initiate an one-off trace.")
            .map_err(err_to_binder_status)
    }
    fn process(&self, blocking: bool) -> BinderResult<()> {
        let lock = &mut *self.lock();
        lock.scheduler
            .process(blocking)
            .context("Failed to process profiles.")
            .map_err(err_to_binder_status)
    }
    fn report(&self) -> BinderResult<String> {
        self.process(true)?;

        let lock = &mut *self.lock();
        pack_report(&PROFILE_OUTPUT_DIR, &REPORT_OUTPUT_DIR, &lock.config)
            .context("Failed to create profile report.")
            .map_err(err_to_binder_status)
    }
    fn delete_report(&self, report_name: &str) -> BinderResult<()> {
        verify_report_name(&report_name).map_err(err_to_binder_status)?;

        let mut report = PathBuf::from(&*REPORT_OUTPUT_DIR);
        report.push(report_name);
        report.set_extension("zip");
        remove_file(&report).ok();
        Ok(())
    }
    fn copy_report_to_bb(&self, bb_profile_id: i32, report_name: &str) -> BinderResult<()> {
        if bb_profile_id < 0 {
            return Err(err_to_binder_status(anyhow!("Invalid profile ID")));
        }
        verify_report_name(&report_name).map_err(err_to_binder_status)?;

        let mut report = PathBuf::from(&*REPORT_OUTPUT_DIR);
        report.push(report_name);
        report.set_extension("zip");

        let mut dest = PathBuf::from(&*BETTERBUG_CACHE_DIR_PREFIX);
        dest.push(bb_profile_id.to_string());
        dest.push(&*BETTERBUG_CACHE_DIR_SUFFIX);
        if !dest.is_dir() {
            return Err(err_to_binder_status(anyhow!("Cannot open BetterBug cache dir")));
        }
        dest.push(report_name);
        dest.set_extension("zip");

        copy(report, dest)
            .map(|_| ())
            .context("Failed to copy report to bb storage.")
            .map_err(err_to_binder_status)
    }
    fn get_supported_provider(&self) -> BinderResult<String> {
        Ok(self.lock().scheduler.get_trace_provider_name().to_string())
    }
}

/// Verify that the report name is valid, i.e. not a relative path component, to prevent potential
/// attack.
fn verify_report_name(report_name: &str) -> Result<()> {
    match report_name.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        true => Ok(()),
        false => bail!("Invalid report name: {}", report_name),
    }
}

impl ProfcollectdBinderService {
    pub fn new() -> Result<Self> {
        let new_scheduler = Scheduler::new()?;
        let new_config = Config::from_env()?;

        let config_changed = read_to_string(*CONFIG_FILE)
            .ok()
            .and_then(|s| Config::from_str(&s).ok())
            .filter(|c| new_config == *c)
            .is_none();

        if config_changed {
            log::info!("Config change detected, clearing traces.");
            remove_dir_all(*PROFILE_OUTPUT_DIR)?;
            remove_dir_all(*TRACE_OUTPUT_DIR)?;
            create_dir(*PROFILE_OUTPUT_DIR)?;
            create_dir(*TRACE_OUTPUT_DIR)?;

            write(*CONFIG_FILE, &new_config.to_string())?;
        }

        Ok(ProfcollectdBinderService {
            lock: Mutex::new(Lock { scheduler: new_scheduler, config: new_config }),
        })
    }

    fn lock(&self) -> MutexGuard<Lock> {
        self.lock.lock().unwrap()
    }
}
