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

//! Rust API for interacting with a remote binder service.

use crate::binder::{
    AsNative, FromIBinder, IBinder, IBinderInternal, Interface, InterfaceClass, Strong,
    TransactionCode, TransactionFlags,
};
use crate::error::{status_result, Result, StatusCode};
use crate::parcel::{
    Deserialize, DeserializeArray, DeserializeOption, Parcel, Serialize, SerializeArray,
    SerializeOption,
};
use crate::sys;

use std::cmp::Ordering;
use std::convert::TryInto;
use std::ffi::{c_void, CString};
use std::fmt;
use std::os::unix::io::AsRawFd;
use std::ptr;

/// A strong reference to a Binder remote object.
///
/// This struct encapsulates the generic C++ `sp<IBinder>` class. This wrapper
/// is untyped; typed interface access is implemented by the AIDL compiler.
pub struct SpIBinder(*mut sys::AIBinder);

impl fmt::Debug for SpIBinder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("SpIBinder")
    }
}

/// # Safety
///
/// An `SpIBinder` is an immutable handle to a C++ IBinder, which is thread-safe
unsafe impl Send for SpIBinder {}

/// # Safety
///
/// An `SpIBinder` is an immutable handle to a C++ IBinder, which is thread-safe
unsafe impl Sync for SpIBinder {}

impl SpIBinder {
    /// Create an `SpIBinder` wrapper object from a raw `AIBinder` pointer.
    ///
    /// # Safety
    ///
    /// This constructor is safe iff `ptr` is a null pointer or a valid pointer
    /// to an `AIBinder`.
    ///
    /// In the non-null case, this method conceptually takes ownership of a strong
    /// reference to the object, so `AIBinder_incStrong` must have been called
    /// on the pointer before passing it to this constructor. This is generally
    /// done by Binder NDK methods that return an `AIBinder`, but care should be
    /// taken to ensure this invariant.
    ///
    /// All `SpIBinder` objects that are constructed will hold a valid pointer
    /// to an `AIBinder`, which will remain valid for the entire lifetime of the
    /// `SpIBinder` (we keep a strong reference, and only decrement on drop).
    pub(crate) unsafe fn from_raw(ptr: *mut sys::AIBinder) -> Option<Self> {
        ptr.as_mut().map(|p| Self(p))
    }

    /// Extract a raw `AIBinder` pointer from this wrapper.
    ///
    /// This method should _only_ be used for testing. Do not try to use the NDK
    /// interface directly for anything else.
    ///
    /// # Safety
    ///
    /// The resulting pointer is valid only as long as the SpIBinder is alive.
    /// The SpIBinder object retains ownership of the AIBinder and the caller
    /// should not attempt to free the returned pointer.
    pub unsafe fn as_raw(&self) -> *mut sys::AIBinder {
        self.0
    }

    /// Return true if this binder object is hosted in a different process than
    /// the current one.
    pub fn is_remote(&self) -> bool {
        unsafe {
            // Safety: `SpIBinder` guarantees that it always contains a valid
            // `AIBinder` pointer.
            sys::AIBinder_isRemote(self.as_native())
        }
    }

    /// Try to convert this Binder object into a trait object for the given
    /// Binder interface.
    ///
    /// If this object does not implement the expected interface, the error
    /// `StatusCode::BAD_TYPE` is returned.
    pub fn into_interface<I: FromIBinder + Interface + ?Sized>(self) -> Result<Strong<I>> {
        FromIBinder::try_from(self)
    }

    /// Return the interface class of this binder object, if associated with
    /// one.
    pub fn get_class(&mut self) -> Option<InterfaceClass> {
        unsafe {
            // Safety: `SpIBinder` guarantees that it always contains a valid
            // `AIBinder` pointer. `AIBinder_getClass` returns either a null
            // pointer or a valid pointer to an `AIBinder_Class`. After mapping
            // null to None, we can safely construct an `InterfaceClass` if the
            // pointer was non-null.
            let class = sys::AIBinder_getClass(self.as_native_mut());
            class.as_ref().map(|p| InterfaceClass::from_ptr(p))
        }
    }

    /// Creates a new weak reference to this binder object.
    pub fn downgrade(&mut self) -> WpIBinder {
        WpIBinder::new(self)
    }
}

pub mod unstable_api {
    use super::{sys, SpIBinder};

    /// A temporary API to allow the client to create a `SpIBinder` from a `sys::AIBinder`. This is
    /// needed to bridge RPC binder, which doesn't have Rust API yet.
    /// TODO(b/184872979): remove once the Rust API is created.
    ///
    /// # Safety
    ///
    /// See `SpIBinder::from_raw`.
    pub unsafe fn new_spibinder(ptr: *mut sys::AIBinder) -> Option<SpIBinder> {
        SpIBinder::from_raw(ptr)
    }
}

/// An object that can be associate with an [`InterfaceClass`].
pub trait AssociateClass {
    /// Check if this object is a valid object for the given interface class
    /// `I`.
    ///
    /// Returns `Some(self)` if this is a valid instance of the interface, and
    /// `None` otherwise.
    ///
    /// Classes constructed by `InterfaceClass` are unique per type, so
    /// repeatedly calling this method for the same `InterfaceClass` is allowed.
    fn associate_class(&mut self, class: InterfaceClass) -> bool;
}

impl AssociateClass for SpIBinder {
    fn associate_class(&mut self, class: InterfaceClass) -> bool {
        unsafe {
            // Safety: `SpIBinder` guarantees that it always contains a valid
            // `AIBinder` pointer. An `InterfaceClass` can always be converted
            // into a valid `AIBinder_Class` pointer, so these parameters are
            // always safe.
            sys::AIBinder_associateClass(self.as_native_mut(), class.into())
        }
    }
}

impl Ord for SpIBinder {
    fn cmp(&self, other: &Self) -> Ordering {
        let less_than = unsafe {
            // Safety: SpIBinder always holds a valid `AIBinder` pointer, so
            // this pointer is always safe to pass to `AIBinder_lt` (null is
            // also safe to pass to this function, but we should never do that).
            sys::AIBinder_lt(self.0, other.0)
        };
        let greater_than = unsafe {
            // Safety: SpIBinder always holds a valid `AIBinder` pointer, so
            // this pointer is always safe to pass to `AIBinder_lt` (null is
            // also safe to pass to this function, but we should never do that).
            sys::AIBinder_lt(other.0, self.0)
        };
        if !less_than && !greater_than {
            Ordering::Equal
        } else if less_than {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for SpIBinder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SpIBinder {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.0, other.0)
    }
}

impl Eq for SpIBinder {}

impl Clone for SpIBinder {
    fn clone(&self) -> Self {
        unsafe {
            // Safety: Cloning a strong reference must increment the reference
            // count. We are guaranteed by the `SpIBinder` constructor
            // invariants that `self.0` is always a valid `AIBinder` pointer.
            sys::AIBinder_incStrong(self.0);
        }
        Self(self.0)
    }
}

impl Drop for SpIBinder {
    // We hold a strong reference to the IBinder in SpIBinder and need to give up
    // this reference on drop.
    fn drop(&mut self) {
        unsafe {
            // Safety: SpIBinder always holds a valid `AIBinder` pointer, so we
            // know this pointer is safe to pass to `AIBinder_decStrong` here.
            sys::AIBinder_decStrong(self.as_native_mut());
        }
    }
}

impl<T: AsNative<sys::AIBinder>> IBinderInternal for T {
    /// Perform a binder transaction
    fn transact<F: FnOnce(&mut Parcel) -> Result<()>>(
        &self,
        code: TransactionCode,
        flags: TransactionFlags,
        input_callback: F,
    ) -> Result<Parcel> {
        let mut input = ptr::null_mut();
        let status = unsafe {
            // Safety: `SpIBinder` guarantees that `self` always contains a
            // valid pointer to an `AIBinder`. It is safe to cast from an
            // immutable pointer to a mutable pointer here, because
            // `AIBinder_prepareTransaction` only calls immutable `AIBinder`
            // methods but the parameter is unfortunately not marked as const.
            //
            // After the call, input will be either a valid, owned `AParcel`
            // pointer, or null.
            sys::AIBinder_prepareTransaction(self.as_native() as *mut sys::AIBinder, &mut input)
        };
        status_result(status)?;
        let mut input = unsafe {
            // Safety: At this point, `input` is either a valid, owned `AParcel`
            // pointer, or null. `Parcel::owned` safely handles both cases,
            // taking ownership of the parcel.
            Parcel::owned(input).ok_or(StatusCode::UNEXPECTED_NULL)?
        };
        input_callback(&mut input)?;
        let mut reply = ptr::null_mut();
        let status = unsafe {
            // Safety: `SpIBinder` guarantees that `self` always contains a
            // valid pointer to an `AIBinder`. Although `IBinder::transact` is
            // not a const method, it is still safe to cast our immutable
            // pointer to mutable for the call. First, `IBinder::transact` is
            // thread-safe, so concurrency is not an issue. The only way that
            // `transact` can affect any visible, mutable state in the current
            // process is by calling `onTransact` for a local service. However,
            // in order for transactions to be thread-safe, this method must
            // dynamically lock its data before modifying it. We enforce this
            // property in Rust by requiring `Sync` for remotable objects and
            // only providing `on_transact` with an immutable reference to
            // `self`.
            //
            // This call takes ownership of the `input` parcel pointer, and
            // passes ownership of the `reply` out parameter to its caller. It
            // does not affect ownership of the `binder` parameter.
            sys::AIBinder_transact(
                self.as_native() as *mut sys::AIBinder,
                code,
                &mut input.into_raw(),
                &mut reply,
                flags,
            )
        };
        status_result(status)?;

        unsafe {
            // Safety: `reply` is either a valid `AParcel` pointer or null
            // after the call to `AIBinder_transact` above, so we can
            // construct a `Parcel` out of it. `AIBinder_transact` passes
            // ownership of the `reply` parcel to Rust, so we need to
            // construct an owned variant. `Parcel::owned` takes ownership
            // of the parcel pointer.
            Parcel::owned(reply).ok_or(StatusCode::UNEXPECTED_NULL)
        }
    }

    fn is_binder_alive(&self) -> bool {
        unsafe {
            // Safety: `SpIBinder` guarantees that `self` always contains a
            // valid pointer to an `AIBinder`.
            //
            // This call does not affect ownership of its pointer parameter.
            sys::AIBinder_isAlive(self.as_native())
        }
    }

    fn ping_binder(&mut self) -> Result<()> {
        let status = unsafe {
            // Safety: `SpIBinder` guarantees that `self` always contains a
            // valid pointer to an `AIBinder`.
            //
            // This call does not affect ownership of its pointer parameter.
            sys::AIBinder_ping(self.as_native_mut())
        };
        status_result(status)
    }

    fn set_requesting_sid(&mut self, enable: bool) {
        unsafe { sys::AIBinder_setRequestingSid(self.as_native_mut(), enable) };
    }

    fn dump<F: AsRawFd>(&mut self, fp: &F, args: &[&str]) -> Result<()> {
        let args: Vec<_> = args.iter().map(|a| CString::new(*a).unwrap()).collect();
        let mut arg_ptrs: Vec<_> = args.iter().map(|a| a.as_ptr()).collect();
        let status = unsafe {
            // Safety: `SpIBinder` guarantees that `self` always contains a
            // valid pointer to an `AIBinder`. `AsRawFd` guarantees that the
            // file descriptor parameter is always be a valid open file. The
            // `args` pointer parameter is a valid pointer to an array of C
            // strings that will outlive the call since `args` lives for the
            // whole function scope.
            //
            // This call does not affect ownership of its binder pointer
            // parameter and does not take ownership of the file or args array
            // parameters.
            sys::AIBinder_dump(
                self.as_native_mut(),
                fp.as_raw_fd(),
                arg_ptrs.as_mut_ptr(),
                arg_ptrs.len().try_into().unwrap(),
            )
        };
        status_result(status)
    }

    fn get_extension(&mut self) -> Result<Option<SpIBinder>> {
        let mut out = ptr::null_mut();
        let status = unsafe {
            // Safety: `SpIBinder` guarantees that `self` always contains a
            // valid pointer to an `AIBinder`. After this call, the `out`
            // parameter will be either null, or a valid pointer to an
            // `AIBinder`.
            //
            // This call passes ownership of the out pointer to its caller
            // (assuming it is set to a non-null value).
            sys::AIBinder_getExtension(self.as_native_mut(), &mut out)
        };
        let ibinder = unsafe {
            // Safety: The call above guarantees that `out` is either null or a
            // valid, owned pointer to an `AIBinder`, both of which are safe to
            // pass to `SpIBinder::from_raw`.
            SpIBinder::from_raw(out)
        };

        status_result(status)?;
        Ok(ibinder)
    }
}

impl<T: AsNative<sys::AIBinder>> IBinder for T {
    fn link_to_death(&mut self, recipient: &mut DeathRecipient) -> Result<()> {
        status_result(unsafe {
            // Safety: `SpIBinder` guarantees that `self` always contains a
            // valid pointer to an `AIBinder`. `recipient` can always be
            // converted into a valid pointer to an
            // `AIBinder_DeathRecipient`. Any value is safe to pass as the
            // cookie, although we depend on this value being set by
            // `get_cookie` when the death recipient callback is called.
            sys::AIBinder_linkToDeath(
                self.as_native_mut(),
                recipient.as_native_mut(),
                recipient.get_cookie(),
            )
        })
    }

    fn unlink_to_death(&mut self, recipient: &mut DeathRecipient) -> Result<()> {
        status_result(unsafe {
            // Safety: `SpIBinder` guarantees that `self` always contains a
            // valid pointer to an `AIBinder`. `recipient` can always be
            // converted into a valid pointer to an
            // `AIBinder_DeathRecipient`. Any value is safe to pass as the
            // cookie, although we depend on this value being set by
            // `get_cookie` when the death recipient callback is called.
            sys::AIBinder_unlinkToDeath(
                self.as_native_mut(),
                recipient.as_native_mut(),
                recipient.get_cookie(),
            )
        })
    }
}

impl Serialize for SpIBinder {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        parcel.write_binder(Some(self))
    }
}

impl SerializeOption for SpIBinder {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        parcel.write_binder(this)
    }
}

impl SerializeArray for SpIBinder {}
impl SerializeArray for Option<&SpIBinder> {}

impl Deserialize for SpIBinder {
    fn deserialize(parcel: &Parcel) -> Result<SpIBinder> {
        parcel
            .read_binder()
            .transpose()
            .unwrap_or(Err(StatusCode::UNEXPECTED_NULL))
    }
}

impl DeserializeOption for SpIBinder {
    fn deserialize_option(parcel: &Parcel) -> Result<Option<SpIBinder>> {
        parcel.read_binder()
    }
}

impl DeserializeArray for SpIBinder {}
impl DeserializeArray for Option<SpIBinder> {}

/// A weak reference to a Binder remote object.
///
/// This struct encapsulates the generic C++ `wp<IBinder>` class. This wrapper
/// is untyped; typed interface access is implemented by the AIDL compiler.
pub struct WpIBinder(*mut sys::AIBinder_Weak);

impl fmt::Debug for WpIBinder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("WpIBinder")
    }
}

/// # Safety
///
/// A `WpIBinder` is an immutable handle to a C++ IBinder, which is thread-safe.
unsafe impl Send for WpIBinder {}

/// # Safety
///
/// A `WpIBinder` is an immutable handle to a C++ IBinder, which is thread-safe.
unsafe impl Sync for WpIBinder {}

impl WpIBinder {
    /// Create a new weak reference from an object that can be converted into a
    /// raw `AIBinder` pointer.
    fn new<B: AsNative<sys::AIBinder>>(binder: &mut B) -> WpIBinder {
        let ptr = unsafe {
            // Safety: `SpIBinder` guarantees that `binder` always contains a
            // valid pointer to an `AIBinder`.
            sys::AIBinder_Weak_new(binder.as_native_mut())
        };
        assert!(!ptr.is_null());
        Self(ptr)
    }

    /// Promote this weak reference to a strong reference to the binder object.
    pub fn promote(&self) -> Option<SpIBinder> {
        unsafe {
            // Safety: `WpIBinder` always contains a valid weak reference, so we
            // can pass this pointer to `AIBinder_Weak_promote`. Returns either
            // null or an AIBinder owned by the caller, both of which are valid
            // to pass to `SpIBinder::from_raw`.
            let ptr = sys::AIBinder_Weak_promote(self.0);
            SpIBinder::from_raw(ptr)
        }
    }
}

impl Clone for WpIBinder {
    fn clone(&self) -> Self {
        let ptr = unsafe {
            // Safety: WpIBinder always holds a valid `AIBinder_Weak` pointer,
            // so this pointer is always safe to pass to `AIBinder_Weak_clone`
            // (although null is also a safe value to pass to this API).
            //
            // We get ownership of the returned pointer, so can construct a new
            // WpIBinder object from it.
            sys::AIBinder_Weak_clone(self.0)
        };
        assert!(
            !ptr.is_null(),
            "Unexpected null pointer from AIBinder_Weak_clone"
        );
        Self(ptr)
    }
}

impl Ord for WpIBinder {
    fn cmp(&self, other: &Self) -> Ordering {
        let less_than = unsafe {
            // Safety: WpIBinder always holds a valid `AIBinder_Weak` pointer,
            // so this pointer is always safe to pass to `AIBinder_Weak_lt`
            // (null is also safe to pass to this function, but we should never
            // do that).
            sys::AIBinder_Weak_lt(self.0, other.0)
        };
        let greater_than = unsafe {
            // Safety: WpIBinder always holds a valid `AIBinder_Weak` pointer,
            // so this pointer is always safe to pass to `AIBinder_Weak_lt`
            // (null is also safe to pass to this function, but we should never
            // do that).
            sys::AIBinder_Weak_lt(other.0, self.0)
        };
        if !less_than && !greater_than {
            Ordering::Equal
        } else if less_than {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for WpIBinder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for WpIBinder {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for WpIBinder {}

impl Drop for WpIBinder {
    fn drop(&mut self) {
        unsafe {
            // Safety: WpIBinder always holds a valid `AIBinder_Weak` pointer, so we
            // know this pointer is safe to pass to `AIBinder_Weak_delete` here.
            sys::AIBinder_Weak_delete(self.0);
        }
    }
}

/// Rust wrapper around DeathRecipient objects.
#[repr(C)]
pub struct DeathRecipient {
    recipient: *mut sys::AIBinder_DeathRecipient,
    callback: Box<dyn Fn() + Send + 'static>,
}

impl DeathRecipient {
    /// Create a new death recipient that will call the given callback when its
    /// associated object dies.
    pub fn new<F>(callback: F) -> DeathRecipient
    where
        F: Fn() + Send + 'static,
    {
        let callback = Box::new(callback);
        let recipient = unsafe {
            // Safety: The function pointer is a valid death recipient callback.
            //
            // This call returns an owned `AIBinder_DeathRecipient` pointer
            // which must be destroyed via `AIBinder_DeathRecipient_delete` when
            // no longer needed.
            sys::AIBinder_DeathRecipient_new(Some(Self::binder_died::<F>))
        };
        DeathRecipient {
            recipient,
            callback,
        }
    }

    /// Get the opaque cookie that identifies this death recipient.
    ///
    /// This cookie will be used to link and unlink this death recipient to a
    /// binder object and will be passed to the `binder_died` callback as an
    /// opaque userdata pointer.
    fn get_cookie(&self) -> *mut c_void {
        &*self.callback as *const _ as *mut c_void
    }

    /// Callback invoked from C++ when the binder object dies.
    ///
    /// # Safety
    ///
    /// The `cookie` parameter must have been created with the `get_cookie`
    /// method of this object.
    unsafe extern "C" fn binder_died<F>(cookie: *mut c_void)
    where
        F: Fn() + Send + 'static,
    {
        let callback = (cookie as *mut F).as_ref().unwrap();
        callback();
    }
}

/// # Safety
///
/// A `DeathRecipient` is always constructed with a valid raw pointer to an
/// `AIBinder_DeathRecipient`, so it is always type-safe to extract this
/// pointer.
unsafe impl AsNative<sys::AIBinder_DeathRecipient> for DeathRecipient {
    fn as_native(&self) -> *const sys::AIBinder_DeathRecipient {
        self.recipient
    }

    fn as_native_mut(&mut self) -> *mut sys::AIBinder_DeathRecipient {
        self.recipient
    }
}

impl Drop for DeathRecipient {
    fn drop(&mut self) {
        unsafe {
            // Safety: `self.recipient` is always a valid, owned
            // `AIBinder_DeathRecipient` pointer returned by
            // `AIBinder_DeathRecipient_new` when `self` was created. This
            // delete method can only be called once when `self` is dropped.
            sys::AIBinder_DeathRecipient_delete(self.recipient);
        }
    }
}

/// Generic interface to remote binder objects.
///
/// Corresponds to the C++ `BpInterface` class.
pub trait Proxy: Sized + Interface {
    /// The Binder interface descriptor string.
    ///
    /// This string is a unique identifier for a Binder interface, and should be
    /// the same between all implementations of that interface.
    fn get_descriptor() -> &'static str;

    /// Create a new interface from the given proxy, if it matches the expected
    /// type of this interface.
    fn from_binder(binder: SpIBinder) -> Result<Self>;
}

/// # Safety
///
/// This is a convenience method that wraps `AsNative` for `SpIBinder` to allow
/// invocation of `IBinder` methods directly from `Interface` objects. It shares
/// the same safety as the implementation for `SpIBinder`.
unsafe impl<T: Proxy> AsNative<sys::AIBinder> for T {
    fn as_native(&self) -> *const sys::AIBinder {
        self.as_binder().as_native()
    }

    fn as_native_mut(&mut self) -> *mut sys::AIBinder {
        self.as_binder().as_native_mut()
    }
}

/// Retrieve an existing service, blocking for a few seconds if it doesn't yet
/// exist.
pub fn get_service(name: &str) -> Option<SpIBinder> {
    let name = CString::new(name).ok()?;
    unsafe {
        // Safety: `AServiceManager_getService` returns either a null pointer or
        // a valid pointer to an owned `AIBinder`. Either of these values is
        // safe to pass to `SpIBinder::from_raw`.
        SpIBinder::from_raw(sys::AServiceManager_getService(name.as_ptr()))
    }
}

/// Retrieve an existing service, or start it if it is configured as a dynamic
/// service and isn't yet started.
pub fn wait_for_service(name: &str) -> Option<SpIBinder> {
    let name = CString::new(name).ok()?;
    unsafe {
        // Safety: `AServiceManager_waitforService` returns either a null
        // pointer or a valid pointer to an owned `AIBinder`. Either of these
        // values is safe to pass to `SpIBinder::from_raw`.
        SpIBinder::from_raw(sys::AServiceManager_waitForService(name.as_ptr()))
    }
}

/// Retrieve an existing service for a particular interface, blocking for a few
/// seconds if it doesn't yet exist.
pub fn get_interface<T: FromIBinder + ?Sized>(name: &str) -> Result<Strong<T>> {
    let service = get_service(name);
    match service {
        Some(service) => FromIBinder::try_from(service),
        None => Err(StatusCode::NAME_NOT_FOUND),
    }
}

/// Retrieve an existing service for a particular interface, or start it if it
/// is configured as a dynamic service and isn't yet started.
pub fn wait_for_interface<T: FromIBinder + ?Sized>(name: &str) -> Result<Strong<T>> {
    let service = wait_for_service(name);
    match service {
        Some(service) => FromIBinder::try_from(service),
        None => Err(StatusCode::NAME_NOT_FOUND),
    }
}

/// # Safety
///
/// `SpIBinder` guarantees that `binder` always contains a valid pointer to an
/// `AIBinder`, so we can trivially extract this pointer here.
unsafe impl AsNative<sys::AIBinder> for SpIBinder {
    fn as_native(&self) -> *const sys::AIBinder {
        self.0
    }

    fn as_native_mut(&mut self) -> *mut sys::AIBinder {
        self.0
    }
}
