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

use crate::binder::AsNative;
use crate::sys;

use std::error;
use std::ffi::CStr;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::result;

pub use sys::binder_status_t as status_t;

/// Low-level status codes from Android `libutils`.
// All error codes are negative integer values. Derived from the anonymous enum
// in utils/Errors.h
pub use sys::android_c_interface_StatusCode as StatusCode;

/// A specialized [`Result`](result::Result) for binder operations.
pub type Result<T> = result::Result<T, StatusCode>;

/// Convert a low-level status code into an empty result.
///
/// An OK status is converted into an `Ok` result, any other status is converted
/// into an `Err` result holding the status code.
pub fn status_result(status: status_t) -> Result<()> {
    match parse_status_code(status) {
        StatusCode::OK => Ok(()),
        e => Err(e),
    }
}

fn parse_status_code(code: i32) -> StatusCode {
    match code {
        e if e == StatusCode::OK as i32 => StatusCode::OK,
        e if e == StatusCode::NO_MEMORY as i32 => StatusCode::NO_MEMORY,
        e if e == StatusCode::INVALID_OPERATION as i32 => StatusCode::INVALID_OPERATION,
        e if e == StatusCode::BAD_VALUE as i32 => StatusCode::BAD_VALUE,
        e if e == StatusCode::BAD_TYPE as i32 => StatusCode::BAD_TYPE,
        e if e == StatusCode::NAME_NOT_FOUND as i32 => StatusCode::NAME_NOT_FOUND,
        e if e == StatusCode::PERMISSION_DENIED as i32 => StatusCode::PERMISSION_DENIED,
        e if e == StatusCode::NO_INIT as i32 => StatusCode::NO_INIT,
        e if e == StatusCode::ALREADY_EXISTS as i32 => StatusCode::ALREADY_EXISTS,
        e if e == StatusCode::DEAD_OBJECT as i32 => StatusCode::DEAD_OBJECT,
        e if e == StatusCode::FAILED_TRANSACTION as i32 => StatusCode::FAILED_TRANSACTION,
        e if e == StatusCode::BAD_INDEX as i32 => StatusCode::BAD_INDEX,
        e if e == StatusCode::NOT_ENOUGH_DATA as i32 => StatusCode::NOT_ENOUGH_DATA,
        e if e == StatusCode::WOULD_BLOCK as i32 => StatusCode::WOULD_BLOCK,
        e if e == StatusCode::TIMED_OUT as i32 => StatusCode::TIMED_OUT,
        e if e == StatusCode::UNKNOWN_TRANSACTION as i32 => StatusCode::UNKNOWN_TRANSACTION,
        e if e == StatusCode::FDS_NOT_ALLOWED as i32 => StatusCode::FDS_NOT_ALLOWED,
        e if e == StatusCode::UNEXPECTED_NULL as i32 => StatusCode::UNEXPECTED_NULL,
        _ => StatusCode::UNKNOWN_ERROR,
    }
}

pub use sys::android_c_interface_ExceptionCode as ExceptionCode;

fn parse_exception_code(code: i32) -> ExceptionCode {
    match code {
        e if e == ExceptionCode::NONE as i32 => ExceptionCode::NONE,
        e if e == ExceptionCode::SECURITY as i32 => ExceptionCode::SECURITY,
        e if e == ExceptionCode::BAD_PARCELABLE as i32 => ExceptionCode::BAD_PARCELABLE,
        e if e == ExceptionCode::ILLEGAL_ARGUMENT as i32 => ExceptionCode::ILLEGAL_ARGUMENT,
        e if e == ExceptionCode::NULL_POINTER as i32 => ExceptionCode::NULL_POINTER,
        e if e == ExceptionCode::ILLEGAL_STATE as i32 => ExceptionCode::ILLEGAL_STATE,
        e if e == ExceptionCode::NETWORK_MAIN_THREAD as i32 => ExceptionCode::NETWORK_MAIN_THREAD,
        e if e == ExceptionCode::UNSUPPORTED_OPERATION as i32 => {
            ExceptionCode::UNSUPPORTED_OPERATION
        }
        e if e == ExceptionCode::SERVICE_SPECIFIC as i32 => ExceptionCode::SERVICE_SPECIFIC,
        _ => ExceptionCode::TRANSACTION_FAILED,
    }
}

// Safety: `Status` always contains a owning pointer to a valid `AStatus`. The
// lifetime of the contained pointer is the same as the `Status` object.
/// High-level binder status object that encapsulates a standard way to keep
/// track of and chain binder errors along with service specific errors.
///
/// Used in AIDL transactions to represent failed transactions.
pub struct Status(*mut sys::AStatus);

// Safety: The `AStatus` that the `Status` points to must have an entirely thread-safe API for the
// duration of the `Status` object's lifetime. We ensure this by not allowing mutation of a `Status`
// in Rust, and the NDK API says we're the owner of our `AStatus` objects so outside code should not
// be mutating them underneath us.
unsafe impl Sync for Status {}

// Safety: `Status` always contains an owning pointer to a global, immutable, interned `AStatus`.
// A thread-local `AStatus` would not be valid.
unsafe impl Send for Status {}

impl Status {
    /// Create a status object representing a successful transaction.
    pub fn ok() -> Self {
        let ptr = unsafe {
            // Safety: `AStatus_newOk` always returns a new, heap allocated
            // pointer to an `ASTatus` object, so we know this pointer will be
            // valid.
            //
            // Rust takes ownership of the returned pointer.
            sys::AStatus_newOk()
        };
        Self(ptr)
    }

    /// Create a status object from a service specific error
    pub fn new_service_specific_error(err: i32, message: Option<&CStr>) -> Status {
        let ptr = if let Some(message) = message {
            unsafe {
                // Safety: Any i32 is a valid service specific error for the
                // error code parameter. We construct a valid, null-terminated
                // `CString` from the message, which must be a valid C-style
                // string to pass as the message. This function always returns a
                // new, heap allocated pointer to an `AStatus` object, so we
                // know the returned pointer will be valid.
                //
                // Rust takes ownership of the returned pointer.
                sys::AStatus_fromServiceSpecificErrorWithMessage(err, message.as_ptr())
            }
        } else {
            unsafe {
                // Safety: Any i32 is a valid service specific error for the
                // error code parameter. This function always returns a new,
                // heap allocated pointer to an `AStatus` object, so we know the
                // returned pointer will be valid.
                //
                // Rust takes ownership of the returned pointer.
                sys::AStatus_fromServiceSpecificError(err)
            }
        };
        Self(ptr)
    }

    /// Create a status object from an exception code
    pub fn new_exception(exception: ExceptionCode, message: Option<&CStr>) -> Status {
        if let Some(message) = message {
            let ptr = unsafe {
                sys::AStatus_fromExceptionCodeWithMessage(exception as i32, message.as_ptr())
            };
            Self(ptr)
        } else {
            exception.into()
        }
    }

    /// Create a status object from a raw `AStatus` pointer.
    ///
    /// # Safety
    ///
    /// This constructor is safe iff `ptr` is a valid pointer to an `AStatus`.
    pub(crate) unsafe fn from_ptr(ptr: *mut sys::AStatus) -> Self {
        Self(ptr)
    }

    /// Returns `true` if this status represents a successful transaction.
    pub fn is_ok(&self) -> bool {
        unsafe {
            // Safety: `Status` always contains a valid `AStatus` pointer, so we
            // are always passing a valid pointer to `AStatus_isOk` here.
            sys::AStatus_isOk(self.as_native())
        }
    }

    /// Returns a description of the status.
    pub fn get_description(&self) -> String {
        let description_ptr = unsafe {
            // Safety: `Status` always contains a valid `AStatus` pointer, so we
            // are always passing a valid pointer to `AStatus_getDescription`
            // here.
            //
            // `AStatus_getDescription` always returns a valid pointer to a null
            // terminated C string. Rust is responsible for freeing this pointer
            // via `AStatus_deleteDescription`.
            sys::AStatus_getDescription(self.as_native())
        };
        let description = unsafe {
            // Safety: `AStatus_getDescription` always returns a valid C string,
            // which can be safely converted to a `CStr`.
            CStr::from_ptr(description_ptr)
        };
        let description = description.to_string_lossy().to_string();
        unsafe {
            // Safety: `description_ptr` was returned from
            // `AStatus_getDescription` above, and must be freed via
            // `AStatus_deleteDescription`. We must not access the pointer after
            // this call, so we copy it into an owned string above and return
            // that string.
            sys::AStatus_deleteDescription(description_ptr);
        }
        description
    }

    /// Returns the exception code of the status.
    pub fn exception_code(&self) -> ExceptionCode {
        let code = unsafe {
            // Safety: `Status` always contains a valid `AStatus` pointer, so we
            // are always passing a valid pointer to `AStatus_getExceptionCode`
            // here.
            sys::AStatus_getExceptionCode(self.as_native())
        };
        parse_exception_code(code)
    }

    /// Return a status code representing a transaction failure, or
    /// `StatusCode::OK` if there was no transaction failure.
    ///
    /// If this method returns `OK`, the status may still represent a different
    /// exception or a service specific error. To find out if this transaction
    /// as a whole is okay, use [`is_ok`](Self::is_ok) instead.
    pub fn transaction_error(&self) -> StatusCode {
        let code = unsafe {
            // Safety: `Status` always contains a valid `AStatus` pointer, so we
            // are always passing a valid pointer to `AStatus_getStatus` here.
            sys::AStatus_getStatus(self.as_native())
        };
        parse_status_code(code)
    }

    /// Return a service specific error if this status represents one.
    ///
    /// This function will only ever return a non-zero result if
    /// [`exception_code`](Self::exception_code) returns
    /// `ExceptionCode::SERVICE_SPECIFIC`. If this function returns 0, the
    /// status object may still represent a different exception or status. To
    /// find out if this transaction as a whole is okay, use
    /// [`is_ok`](Self::is_ok) instead.
    pub fn service_specific_error(&self) -> i32 {
        unsafe {
            // Safety: `Status` always contains a valid `AStatus` pointer, so we
            // are always passing a valid pointer to
            // `AStatus_getServiceSpecificError` here.
            sys::AStatus_getServiceSpecificError(self.as_native())
        }
    }

    /// Calls `op` if the status was ok, otherwise returns an `Err` value of
    /// `self`.
    pub fn and_then<T, F>(self, op: F) -> result::Result<T, Status>
    where
        F: FnOnce() -> result::Result<T, Status>,
    {
        <result::Result<(), Status>>::from(self)?;
        op()
    }
}

impl error::Error for Status {}

impl Display for Status {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(&self.get_description())
    }
}

impl Debug for Status {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(&self.get_description())
    }
}

impl PartialEq for Status {
    fn eq(&self, other: &Status) -> bool {
        let self_code = self.exception_code();
        let other_code = other.exception_code();

        match (self_code, other_code) {
            (ExceptionCode::NONE, ExceptionCode::NONE) => true,
            (ExceptionCode::TRANSACTION_FAILED, ExceptionCode::TRANSACTION_FAILED) => {
                self.transaction_error() == other.transaction_error()
                    && self.get_description() == other.get_description()
            }
            (ExceptionCode::SERVICE_SPECIFIC, ExceptionCode::SERVICE_SPECIFIC) => {
                self.service_specific_error() == other.service_specific_error()
                    && self.get_description() == other.get_description()
            }
            (e1, e2) => e1 == e2 && self.get_description() == other.get_description(),
        }
    }
}

impl Eq for Status {}

impl From<StatusCode> for Status {
    fn from(status: StatusCode) -> Status {
        (status as status_t).into()
    }
}

impl From<status_t> for Status {
    fn from(status: status_t) -> Status {
        let ptr = unsafe {
            // Safety: `AStatus_fromStatus` expects any `status_t` integer, so
            // this is a safe FFI call. Unknown values will be coerced into
            // UNKNOWN_ERROR.
            sys::AStatus_fromStatus(status)
        };
        Self(ptr)
    }
}

impl From<ExceptionCode> for Status {
    fn from(code: ExceptionCode) -> Status {
        let ptr = unsafe {
            // Safety: `AStatus_fromExceptionCode` expects any
            // `binder_exception_t` (i32) integer, so this is a safe FFI call.
            // Unknown values will be coerced into EX_TRANSACTION_FAILED.
            sys::AStatus_fromExceptionCode(code as i32)
        };
        Self(ptr)
    }
}

// TODO: impl Try for Status when try_trait is stabilized
// https://github.com/rust-lang/rust/issues/42327
impl From<Status> for result::Result<(), Status> {
    fn from(status: Status) -> result::Result<(), Status> {
        if status.is_ok() {
            Ok(())
        } else {
            Err(status)
        }
    }
}

impl From<Status> for status_t {
    fn from(status: Status) -> status_t {
        status.transaction_error() as status_t
    }
}

impl Drop for Status {
    fn drop(&mut self) {
        unsafe {
            // Safety: `Status` manages the lifetime of its inner `AStatus`
            // pointee, so we need to delete it here. We know that the pointer
            // will be valid here since `Status` always contains a valid pointer
            // while it is alive.
            sys::AStatus_delete(self.0);
        }
    }
}

/// # Safety
///
/// `Status` always contains a valid pointer to an `AStatus` object, so we can
/// trivially convert it to a correctly-typed raw pointer.
///
/// Care must be taken that the returned pointer is only dereferenced while the
/// `Status` object is still alive.
unsafe impl AsNative<sys::AStatus> for Status {
    fn as_native(&self) -> *const sys::AStatus {
        self.0
    }

    fn as_native_mut(&mut self) -> *mut sys::AStatus {
        self.0
    }
}
