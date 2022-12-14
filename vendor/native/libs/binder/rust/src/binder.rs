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

//! Trait definitions for binder objects

use crate::error::{status_t, Result, StatusCode};
use crate::parcel::{BorrowedParcel, Parcel};
use crate::proxy::{DeathRecipient, SpIBinder, WpIBinder};
use crate::sys;

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::ffi::{c_void, CStr, CString};
use std::fmt;
use std::fs::File;
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::ptr;

/// Binder action to perform.
///
/// This must be a number between [`FIRST_CALL_TRANSACTION`] and
/// [`LAST_CALL_TRANSACTION`].
pub type TransactionCode = u32;

/// Additional operation flags.
///
/// `FLAG_*` values.
pub type TransactionFlags = u32;

/// Super-trait for Binder interfaces.
///
/// This trait allows conversion of a Binder interface trait object into an
/// IBinder object for IPC calls. All Binder remotable interface (i.e. AIDL
/// interfaces) must implement this trait.
///
/// This is equivalent `IInterface` in C++.
pub trait Interface: Send + Sync {
    /// Convert this binder object into a generic [`SpIBinder`] reference.
    fn as_binder(&self) -> SpIBinder {
        panic!("This object was not a Binder object and cannot be converted into an SpIBinder.")
    }

    /// Dump transaction handler for this Binder object.
    ///
    /// This handler is a no-op by default and should be implemented for each
    /// Binder service struct that wishes to respond to dump transactions.
    fn dump(&self, _file: &File, _args: &[&CStr]) -> Result<()> {
        Ok(())
    }
}

/// Implemented by sync interfaces to specify what the associated async interface is.
/// Generic to handle the fact that async interfaces are generic over a thread pool.
///
/// The binder in any object implementing this trait should be compatible with the
/// `Target` associated type, and using `FromIBinder` to convert it to the target
/// should not fail.
pub trait ToAsyncInterface<P>
where
    Self: Interface,
    Self::Target: FromIBinder,
{
    /// The async interface associated with this sync interface.
    type Target: ?Sized;
}

/// Implemented by async interfaces to specify what the associated sync interface is.
///
/// The binder in any object implementing this trait should be compatible with the
/// `Target` associated type, and using `FromIBinder` to convert it to the target
/// should not fail.
pub trait ToSyncInterface
where
    Self: Interface,
    Self::Target: FromIBinder,
{
    /// The sync interface associated with this async interface.
    type Target: ?Sized;
}

/// Interface stability promise
///
/// An interface can promise to be a stable vendor interface ([`Vintf`]), or
/// makes no stability guarantees ([`Local`]). [`Local`] is
/// currently the default stability.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Stability {
    /// Default stability, visible to other modules in the same compilation
    /// context (e.g. modules on system.img)
    #[default]
    Local,

    /// A Vendor Interface Object, which promises to be stable
    Vintf,
}

impl From<Stability> for i32 {
    fn from(stability: Stability) -> i32 {
        use Stability::*;
        match stability {
            Local => 0,
            Vintf => 1,
        }
    }
}

impl TryFrom<i32> for Stability {
    type Error = StatusCode;
    fn try_from(stability: i32) -> Result<Stability> {
        use Stability::*;
        match stability {
            0 => Ok(Local),
            1 => Ok(Vintf),
            _ => Err(StatusCode::BAD_VALUE),
        }
    }
}

/// A local service that can be remotable via Binder.
///
/// An object that implement this interface made be made into a Binder service
/// via `Binder::new(object)`.
///
/// This is a low-level interface that should normally be automatically
/// generated from AIDL via the [`declare_binder_interface!`] macro. When using
/// the AIDL backend, users need only implement the high-level AIDL-defined
/// interface. The AIDL compiler then generates a container struct that wraps
/// the user-defined service and implements `Remotable`.
pub trait Remotable: Send + Sync {
    /// The Binder interface descriptor string.
    ///
    /// This string is a unique identifier for a Binder interface, and should be
    /// the same between all implementations of that interface.
    fn get_descriptor() -> &'static str;

    /// Handle and reply to a request to invoke a transaction on this object.
    ///
    /// `reply` may be [`None`] if the sender does not expect a reply.
    fn on_transact(
        &self,
        code: TransactionCode,
        data: &BorrowedParcel<'_>,
        reply: &mut BorrowedParcel<'_>,
    ) -> Result<()>;

    /// Handle a request to invoke the dump transaction on this
    /// object.
    fn on_dump(&self, file: &File, args: &[&CStr]) -> Result<()>;

    /// Retrieve the class of this remote object.
    ///
    /// This method should always return the same InterfaceClass for the same
    /// type.
    fn get_class() -> InterfaceClass;
}

/// First transaction code available for user commands (inclusive)
pub const FIRST_CALL_TRANSACTION: TransactionCode = sys::FIRST_CALL_TRANSACTION;
/// Last transaction code available for user commands (inclusive)
pub const LAST_CALL_TRANSACTION: TransactionCode = sys::LAST_CALL_TRANSACTION;

/// Corresponds to TF_ONE_WAY -- an asynchronous call.
pub const FLAG_ONEWAY: TransactionFlags = sys::FLAG_ONEWAY;
/// Corresponds to TF_CLEAR_BUF -- clear transaction buffers after call is made.
pub const FLAG_CLEAR_BUF: TransactionFlags = sys::FLAG_CLEAR_BUF;
/// Set to the vendor flag if we are building for the VNDK, 0 otherwise
pub const FLAG_PRIVATE_LOCAL: TransactionFlags = sys::FLAG_PRIVATE_LOCAL;

/// Internal interface of binder local or remote objects for making
/// transactions.
///
/// This trait corresponds to the parts of the interface of the C++ `IBinder`
/// class which are internal implementation details.
pub trait IBinderInternal: IBinder {
    /// Is this object still alive?
    fn is_binder_alive(&self) -> bool;

    /// Indicate that the service intends to receive caller security contexts.
    #[cfg(not(android_vndk))]
    fn set_requesting_sid(&mut self, enable: bool);

    /// Dump this object to the given file handle
    fn dump<F: AsRawFd>(&mut self, fp: &F, args: &[&str]) -> Result<()>;

    /// Get a new interface that exposes additional extension functionality, if
    /// available.
    fn get_extension(&mut self) -> Result<Option<SpIBinder>>;

    /// Create a Parcel that can be used with `submit_transact`.
    fn prepare_transact(&self) -> Result<Parcel>;

    /// Perform a generic operation with the object.
    ///
    /// The provided [`Parcel`] must have been created by a call to
    /// `prepare_transact` on the same binder.
    ///
    /// # Arguments
    ///
    /// * `code` - Transaction code for the operation.
    /// * `data` - [`Parcel`] with input data.
    /// * `flags` - Transaction flags, e.g. marking the transaction as
    ///   asynchronous ([`FLAG_ONEWAY`](FLAG_ONEWAY)).
    fn submit_transact(
        &self,
        code: TransactionCode,
        data: Parcel,
        flags: TransactionFlags,
    ) -> Result<Parcel>;

    /// Perform a generic operation with the object. This is a convenience
    /// method that internally calls `prepare_transact` followed by
    /// `submit_transact.
    ///
    /// # Arguments
    /// * `code` - Transaction code for the operation
    /// * `flags` - Transaction flags, e.g. marking the transaction as
    ///   asynchronous ([`FLAG_ONEWAY`](FLAG_ONEWAY))
    /// * `input_callback` A callback for building the `Parcel`.
    fn transact<F: FnOnce(BorrowedParcel<'_>) -> Result<()>>(
        &self,
        code: TransactionCode,
        flags: TransactionFlags,
        input_callback: F,
    ) -> Result<Parcel> {
        let mut parcel = self.prepare_transact()?;
        input_callback(parcel.borrowed())?;
        self.submit_transact(code, parcel, flags)
    }
}

/// Interface of binder local or remote objects.
///
/// This trait corresponds to the parts of the interface of the C++ `IBinder`
/// class which are public.
pub trait IBinder {
    /// Register the recipient for a notification if this binder
    /// goes away. If this binder object unexpectedly goes away
    /// (typically because its hosting process has been killed),
    /// then the `DeathRecipient`'s callback will be called.
    ///
    /// You will only receive death notifications for remote binders,
    /// as local binders by definition can't die without you dying as well.
    /// Trying to use this function on a local binder will result in an
    /// INVALID_OPERATION code being returned and nothing happening.
    ///
    /// This link always holds a weak reference to its recipient.
    fn link_to_death(&mut self, recipient: &mut DeathRecipient) -> Result<()>;

    /// Remove a previously registered death notification.
    /// The recipient will no longer be called if this object
    /// dies.
    fn unlink_to_death(&mut self, recipient: &mut DeathRecipient) -> Result<()>;

    /// Send a ping transaction to this object
    fn ping_binder(&mut self) -> Result<()>;
}

/// Opaque reference to the type of a Binder interface.
///
/// This object encapsulates the Binder interface descriptor string, along with
/// the binder transaction callback, if the class describes a local service.
///
/// A Binder remotable object may only have a single interface class, and any
/// given object can only be associated with one class. Two objects with
/// different classes are incompatible, even if both classes have the same
/// interface descriptor.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct InterfaceClass(*const sys::AIBinder_Class);

impl InterfaceClass {
    /// Get a Binder NDK `AIBinder_Class` pointer for this object type.
    ///
    /// Note: the returned pointer will not be constant. Calling this method
    /// multiple times for the same type will result in distinct class
    /// pointers. A static getter for this value is implemented in
    /// [`declare_binder_interface!`].
    pub fn new<I: InterfaceClassMethods>() -> InterfaceClass {
        let descriptor = CString::new(I::get_descriptor()).unwrap();
        let ptr = unsafe {
            // Safety: `AIBinder_Class_define` expects a valid C string, and
            // three valid callback functions, all non-null pointers. The C
            // string is copied and need not be valid for longer than the call,
            // so we can drop it after the call. We can safely assign null to
            // the onDump and handleShellCommand callbacks as long as the class
            // pointer was non-null. Rust None for a Option<fn> is guaranteed to
            // be a NULL pointer. Rust retains ownership of the pointer after it
            // is defined.
            let class = sys::AIBinder_Class_define(
                descriptor.as_ptr(),
                Some(I::on_create),
                Some(I::on_destroy),
                Some(I::on_transact),
            );
            if class.is_null() {
                panic!("Expected non-null class pointer from AIBinder_Class_define!");
            }
            sys::AIBinder_Class_setOnDump(class, Some(I::on_dump));
            sys::AIBinder_Class_setHandleShellCommand(class, None);
            class
        };
        InterfaceClass(ptr)
    }

    /// Construct an `InterfaceClass` out of a raw, non-null `AIBinder_Class`
    /// pointer.
    ///
    /// # Safety
    ///
    /// This function is safe iff `ptr` is a valid, non-null pointer to an
    /// `AIBinder_Class`.
    pub(crate) unsafe fn from_ptr(ptr: *const sys::AIBinder_Class) -> InterfaceClass {
        InterfaceClass(ptr)
    }

    /// Get the interface descriptor string of this class.
    pub fn get_descriptor(&self) -> String {
        unsafe {
            // SAFETY: The descriptor returned by AIBinder_Class_getDescriptor
            // is always a two-byte null terminated sequence of u16s. Thus, we
            // can continue reading from the pointer until we hit a null value,
            // and this pointer can be a valid slice if the slice length is <=
            // the number of u16 elements before the null terminator.

            let raw_descriptor: *const c_char = sys::AIBinder_Class_getDescriptor(self.0);
            CStr::from_ptr(raw_descriptor)
                .to_str()
                .expect("Expected valid UTF-8 string from AIBinder_Class_getDescriptor")
                .into()
        }
    }
}

impl From<InterfaceClass> for *const sys::AIBinder_Class {
    fn from(class: InterfaceClass) -> *const sys::AIBinder_Class {
        class.0
    }
}

/// Strong reference to a binder object
pub struct Strong<I: FromIBinder + ?Sized>(Box<I>);

impl<I: FromIBinder + ?Sized> Strong<I> {
    /// Create a new strong reference to the provided binder object
    pub fn new(binder: Box<I>) -> Self {
        Self(binder)
    }

    /// Construct a new weak reference to this binder
    pub fn downgrade(this: &Strong<I>) -> Weak<I> {
        Weak::new(this)
    }

    /// Convert this synchronous binder handle into an asynchronous one.
    pub fn into_async<P>(self) -> Strong<<I as ToAsyncInterface<P>>::Target>
    where
        I: ToAsyncInterface<P>,
    {
        // By implementing the ToAsyncInterface trait, it is guaranteed that the binder
        // object is also valid for the target type.
        FromIBinder::try_from(self.0.as_binder()).unwrap()
    }

    /// Convert this asynchronous binder handle into a synchronous one.
    pub fn into_sync(self) -> Strong<<I as ToSyncInterface>::Target>
    where
        I: ToSyncInterface,
    {
        // By implementing the ToSyncInterface trait, it is guaranteed that the binder
        // object is also valid for the target type.
        FromIBinder::try_from(self.0.as_binder()).unwrap()
    }
}

impl<I: FromIBinder + ?Sized> Clone for Strong<I> {
    fn clone(&self) -> Self {
        // Since we hold a strong reference, we should always be able to create
        // a new strong reference to the same interface type, so try_from()
        // should never fail here.
        FromIBinder::try_from(self.0.as_binder()).unwrap()
    }
}

impl<I: FromIBinder + ?Sized> Borrow<I> for Strong<I> {
    fn borrow(&self) -> &I {
        &self.0
    }
}

impl<I: FromIBinder + ?Sized> AsRef<I> for Strong<I> {
    fn as_ref(&self) -> &I {
        &self.0
    }
}

impl<I: FromIBinder + ?Sized> Deref for Strong<I> {
    type Target = I;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<I: FromIBinder + fmt::Debug + ?Sized> fmt::Debug for Strong<I> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<I: FromIBinder + ?Sized> Ord for Strong<I> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_binder().cmp(&other.0.as_binder())
    }
}

impl<I: FromIBinder + ?Sized> PartialOrd for Strong<I> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.as_binder().partial_cmp(&other.0.as_binder())
    }
}

impl<I: FromIBinder + ?Sized> PartialEq for Strong<I> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_binder().eq(&other.0.as_binder())
    }
}

impl<I: FromIBinder + ?Sized> Eq for Strong<I> {}

/// Weak reference to a binder object
#[derive(Debug)]
pub struct Weak<I: FromIBinder + ?Sized> {
    weak_binder: WpIBinder,
    interface_type: PhantomData<I>,
}

impl<I: FromIBinder + ?Sized> Weak<I> {
    /// Construct a new weak reference from a strong reference
    fn new(binder: &Strong<I>) -> Self {
        let weak_binder = binder.as_binder().downgrade();
        Weak { weak_binder, interface_type: PhantomData }
    }

    /// Upgrade this weak reference to a strong reference if the binder object
    /// is still alive
    pub fn upgrade(&self) -> Result<Strong<I>> {
        self.weak_binder.promote().ok_or(StatusCode::DEAD_OBJECT).and_then(FromIBinder::try_from)
    }
}

impl<I: FromIBinder + ?Sized> Clone for Weak<I> {
    fn clone(&self) -> Self {
        Self { weak_binder: self.weak_binder.clone(), interface_type: PhantomData }
    }
}

impl<I: FromIBinder + ?Sized> Ord for Weak<I> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.weak_binder.cmp(&other.weak_binder)
    }
}

impl<I: FromIBinder + ?Sized> PartialOrd for Weak<I> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.weak_binder.partial_cmp(&other.weak_binder)
    }
}

impl<I: FromIBinder + ?Sized> PartialEq for Weak<I> {
    fn eq(&self, other: &Self) -> bool {
        self.weak_binder == other.weak_binder
    }
}

impl<I: FromIBinder + ?Sized> Eq for Weak<I> {}

/// Create a function implementing a static getter for an interface class.
///
/// Each binder interface (i.e. local [`Remotable`] service or remote proxy
/// [`Interface`]) must have global, static class that uniquely identifies
/// it. This macro implements an [`InterfaceClass`] getter to simplify these
/// implementations.
///
/// The type of a structure that implements [`InterfaceClassMethods`] must be
/// passed to this macro. For local services, this should be `Binder<Self>`
/// since [`Binder`] implements [`InterfaceClassMethods`].
///
/// # Examples
///
/// When implementing a local [`Remotable`] service `ExampleService`, the
/// `get_class` method is required in the [`Remotable`] impl block. This macro
/// should be used as follows to implement this functionality:
///
/// ```rust
/// impl Remotable for ExampleService {
///     fn get_descriptor() -> &'static str {
///         "android.os.IExampleInterface"
///     }
///
///     fn on_transact(
///         &self,
///         code: TransactionCode,
///         data: &BorrowedParcel,
///         reply: &mut BorrowedParcel,
///     ) -> Result<()> {
///         // ...
///     }
///
///     binder_fn_get_class!(Binder<Self>);
/// }
/// ```
macro_rules! binder_fn_get_class {
    ($class:ty) => {
        binder_fn_get_class!($crate::binder_impl::InterfaceClass::new::<$class>());
    };

    ($constructor:expr) => {
        fn get_class() -> $crate::binder_impl::InterfaceClass {
            static CLASS_INIT: std::sync::Once = std::sync::Once::new();
            static mut CLASS: Option<$crate::binder_impl::InterfaceClass> = None;

            CLASS_INIT.call_once(|| unsafe {
                // Safety: This assignment is guarded by the `CLASS_INIT` `Once`
                // variable, and therefore is thread-safe, as it can only occur
                // once.
                CLASS = Some($constructor);
            });
            unsafe {
                // Safety: The `CLASS` variable can only be mutated once, above,
                // and is subsequently safe to read from any thread.
                CLASS.unwrap()
            }
        }
    };
}

pub trait InterfaceClassMethods {
    /// Get the interface descriptor string for this object type.
    fn get_descriptor() -> &'static str
    where
        Self: Sized;

    /// Called during construction of a new `AIBinder` object of this interface
    /// class.
    ///
    /// The opaque pointer parameter will be the parameter provided to
    /// `AIBinder_new`. Returns an opaque userdata to be associated with the new
    /// `AIBinder` object.
    ///
    /// # Safety
    ///
    /// Callback called from C++. The parameter argument provided to
    /// `AIBinder_new` must match the type expected here. The `AIBinder` object
    /// will take ownership of the returned pointer, which it will free via
    /// `on_destroy`.
    unsafe extern "C" fn on_create(args: *mut c_void) -> *mut c_void;

    /// Called when a transaction needs to be processed by the local service
    /// implementation.
    ///
    /// # Safety
    ///
    /// Callback called from C++. The `binder` parameter must be a valid pointer
    /// to a binder object of this class with userdata initialized via this
    /// class's `on_create`. The parcel parameters must be valid pointers to
    /// parcel objects.
    unsafe extern "C" fn on_transact(
        binder: *mut sys::AIBinder,
        code: u32,
        data: *const sys::AParcel,
        reply: *mut sys::AParcel,
    ) -> status_t;

    /// Called whenever an `AIBinder` object is no longer referenced and needs
    /// to be destroyed.
    ///
    /// # Safety
    ///
    /// Callback called from C++. The opaque pointer parameter must be the value
    /// returned by `on_create` for this class. This function takes ownership of
    /// the provided pointer and destroys it.
    unsafe extern "C" fn on_destroy(object: *mut c_void);

    /// Called to handle the `dump` transaction.
    ///
    /// # Safety
    ///
    /// Must be called with a non-null, valid pointer to a local `AIBinder` that
    /// contains a `T` pointer in its user data. fd should be a non-owned file
    /// descriptor, and args must be an array of null-terminated string
    /// poiinters with length num_args.
    unsafe extern "C" fn on_dump(
        binder: *mut sys::AIBinder,
        fd: i32,
        args: *mut *const c_char,
        num_args: u32,
    ) -> status_t;
}

/// Interface for transforming a generic SpIBinder into a specific remote
/// interface trait.
///
/// # Example
///
/// For Binder interface `IFoo`, the following implementation should be made:
/// ```no_run
/// # use binder::{FromIBinder, SpIBinder, Result};
/// # trait IFoo {}
/// impl FromIBinder for dyn IFoo {
///     fn try_from(ibinder: SpIBinder) -> Result<Box<Self>> {
///         // ...
///         # Err(binder::StatusCode::OK)
///     }
/// }
/// ```
pub trait FromIBinder: Interface {
    /// Try to interpret a generic Binder object as this interface.
    ///
    /// Returns a trait object for the `Self` interface if this object
    /// implements that interface.
    fn try_from(ibinder: SpIBinder) -> Result<Strong<Self>>;
}

/// Trait for transparent Rust wrappers around android C++ native types.
///
/// The pointer return by this trait's methods should be immediately passed to
/// C++ and not stored by Rust. The pointer is valid only as long as the
/// underlying C++ object is alive, so users must be careful to take this into
/// account, as Rust cannot enforce this.
///
/// # Safety
///
/// For this trait to be a correct implementation, `T` must be a valid android
/// C++ type. Since we cannot constrain this via the type system, this trait is
/// marked as unsafe.
pub unsafe trait AsNative<T> {
    /// Return a pointer to the native version of `self`
    fn as_native(&self) -> *const T;

    /// Return a mutable pointer to the native version of `self`
    fn as_native_mut(&mut self) -> *mut T;
}

unsafe impl<T, V: AsNative<T>> AsNative<T> for Option<V> {
    fn as_native(&self) -> *const T {
        self.as_ref().map_or(ptr::null(), |v| v.as_native())
    }

    fn as_native_mut(&mut self) -> *mut T {
        self.as_mut().map_or(ptr::null_mut(), |v| v.as_native_mut())
    }
}

/// The features to enable when creating a native Binder.
///
/// This should always be initialised with a default value, e.g.:
/// ```
/// # use binder::BinderFeatures;
/// BinderFeatures {
///   set_requesting_sid: true,
///   ..BinderFeatures::default(),
/// }
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BinderFeatures {
    /// Indicates that the service intends to receive caller security contexts. This must be true
    /// for `ThreadState::with_calling_sid` to work.
    #[cfg(not(android_vndk))]
    pub set_requesting_sid: bool,
    // Ensure that clients include a ..BinderFeatures::default() to preserve backwards compatibility
    // when new fields are added. #[non_exhaustive] doesn't work because it prevents struct
    // expressions entirely.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

/// Declare typed interfaces for a binder object.
///
/// Given an interface trait and descriptor string, create a native and remote
/// proxy wrapper for this interface. The native service object (`$native`)
/// implements `Remotable` and will dispatch to the function `$on_transact` to
/// handle transactions. The typed proxy object (`$proxy`) wraps remote binder
/// objects for this interface and can optionally contain additional fields.
///
/// Assuming the interface trait is `Interface`, `$on_transact` function must
/// have the following type:
///
/// ```
/// # use binder::{Interface, TransactionCode, BorrowedParcel};
/// # trait Placeholder {
/// fn on_transact(
///     service: &dyn Interface,
///     code: TransactionCode,
///     data: &BorrowedParcel,
///     reply: &mut BorrowedParcel,
/// ) -> binder::Result<()>;
/// # }
/// ```
///
/// # Examples
///
/// The following example declares the local service type `BnServiceManager` and
/// a remote proxy type `BpServiceManager` (the `n` and `p` stand for native and
/// proxy respectively) for the `IServiceManager` Binder interface. The
/// interfaces will be identified by the descriptor string
/// "android.os.IServiceManager". The local service will dispatch transactions
/// using the provided function, `on_transact`.
///
/// ```
/// use binder::{declare_binder_interface, Binder, Interface, TransactionCode, BorrowedParcel};
///
/// pub trait IServiceManager: Interface {
///     // remote methods...
/// }
///
/// declare_binder_interface! {
///     IServiceManager["android.os.IServiceManager"] {
///         native: BnServiceManager(on_transact),
///         proxy: BpServiceManager,
///     }
/// }
///
/// fn on_transact(
///     service: &dyn IServiceManager,
///     code: TransactionCode,
///     data: &BorrowedParcel,
///     reply: &mut BorrowedParcel,
/// ) -> binder::Result<()> {
///     // ...
///     Ok(())
/// }
///
/// impl IServiceManager for BpServiceManager {
///     // parceling/unparceling code for the IServiceManager emitted here
/// }
///
/// impl IServiceManager for Binder<BnServiceManager> {
///     // Forward calls to local implementation
/// }
/// ```
#[macro_export]
macro_rules! declare_binder_interface {
    {
        $interface:path[$descriptor:expr] {
            native: $native:ident($on_transact:path),
            proxy: $proxy:ident,
            $(async: $async_interface:ident,)?
        }
    } => {
        $crate::declare_binder_interface! {
            $interface[$descriptor] {
                native: $native($on_transact),
                proxy: $proxy {},
                $(async: $async_interface,)?
                stability: $crate::binder_impl::Stability::default(),
            }
        }
    };

    {
        $interface:path[$descriptor:expr] {
            native: $native:ident($on_transact:path),
            proxy: $proxy:ident,
            $(async: $async_interface:ident,)?
            stability: $stability:expr,
        }
    } => {
        $crate::declare_binder_interface! {
            $interface[$descriptor] {
                native: $native($on_transact),
                proxy: $proxy {},
                $(async: $async_interface,)?
                stability: $stability,
            }
        }
    };

    {
        $interface:path[$descriptor:expr] {
            native: $native:ident($on_transact:path),
            proxy: $proxy:ident {
                $($fname:ident: $fty:ty = $finit:expr),*
            },
            $(async: $async_interface:ident,)?
        }
    } => {
        $crate::declare_binder_interface! {
            $interface[$descriptor] {
                native: $native($on_transact),
                proxy: $proxy {
                    $($fname: $fty = $finit),*
                },
                $(async: $async_interface,)?
                stability: $crate::binder_impl::Stability::default(),
            }
        }
    };

    {
        $interface:path[$descriptor:expr] {
            native: $native:ident($on_transact:path),
            proxy: $proxy:ident {
                $($fname:ident: $fty:ty = $finit:expr),*
            },
            $(async: $async_interface:ident,)?
            stability: $stability:expr,
        }
    } => {
        $crate::declare_binder_interface! {
            $interface[$descriptor] {
                @doc[concat!("A binder [`Remotable`]($crate::binder_impl::Remotable) that holds an [`", stringify!($interface), "`] object.")]
                native: $native($on_transact),
                @doc[concat!("A binder [`Proxy`]($crate::binder_impl::Proxy) that holds an [`", stringify!($interface), "`] remote interface.")]
                proxy: $proxy {
                    $($fname: $fty = $finit),*
                },
                $(async: $async_interface,)?
                stability: $stability,
            }
        }
    };

    {
        $interface:path[$descriptor:expr] {
            @doc[$native_doc:expr]
            native: $native:ident($on_transact:path),

            @doc[$proxy_doc:expr]
            proxy: $proxy:ident {
                $($fname:ident: $fty:ty = $finit:expr),*
            },

            $( async: $async_interface:ident, )?

            stability: $stability:expr,
        }
    } => {
        #[doc = $proxy_doc]
        pub struct $proxy {
            binder: $crate::SpIBinder,
            $($fname: $fty,)*
        }

        impl $crate::Interface for $proxy {
            fn as_binder(&self) -> $crate::SpIBinder {
                self.binder.clone()
            }
        }

        impl $crate::binder_impl::Proxy for $proxy
        where
            $proxy: $interface,
        {
            fn get_descriptor() -> &'static str {
                $descriptor
            }

            fn from_binder(mut binder: $crate::SpIBinder) -> std::result::Result<Self, $crate::StatusCode> {
                Ok(Self { binder, $($fname: $finit),* })
            }
        }

        #[doc = $native_doc]
        #[repr(transparent)]
        pub struct $native(Box<dyn $interface + Sync + Send + 'static>);

        impl $native {
            /// Create a new binder service.
            pub fn new_binder<T: $interface + Sync + Send + 'static>(inner: T, features: $crate::BinderFeatures) -> $crate::Strong<dyn $interface> {
                let mut binder = $crate::binder_impl::Binder::new_with_stability($native(Box::new(inner)), $stability);
                #[cfg(not(android_vndk))]
                $crate::binder_impl::IBinderInternal::set_requesting_sid(&mut binder, features.set_requesting_sid);
                $crate::Strong::new(Box::new(binder))
            }
        }

        impl $crate::binder_impl::Remotable for $native {
            fn get_descriptor() -> &'static str {
                $descriptor
            }

            fn on_transact(&self, code: $crate::binder_impl::TransactionCode, data: &$crate::binder_impl::BorrowedParcel<'_>, reply: &mut $crate::binder_impl::BorrowedParcel<'_>) -> std::result::Result<(), $crate::StatusCode> {
                match $on_transact(&*self.0, code, data, reply) {
                    // The C++ backend converts UNEXPECTED_NULL into an exception
                    Err($crate::StatusCode::UNEXPECTED_NULL) => {
                        let status = $crate::Status::new_exception(
                            $crate::ExceptionCode::NULL_POINTER,
                            None,
                        );
                        reply.write(&status)
                    },
                    result => result
                }
            }

            fn on_dump(&self, file: &std::fs::File, args: &[&std::ffi::CStr]) -> std::result::Result<(), $crate::StatusCode> {
                self.0.dump(file, args)
            }

            fn get_class() -> $crate::binder_impl::InterfaceClass {
                static CLASS_INIT: std::sync::Once = std::sync::Once::new();
                static mut CLASS: Option<$crate::binder_impl::InterfaceClass> = None;

                CLASS_INIT.call_once(|| unsafe {
                    // Safety: This assignment is guarded by the `CLASS_INIT` `Once`
                    // variable, and therefore is thread-safe, as it can only occur
                    // once.
                    CLASS = Some($crate::binder_impl::InterfaceClass::new::<$crate::binder_impl::Binder<$native>>());
                });
                unsafe {
                    // Safety: The `CLASS` variable can only be mutated once, above,
                    // and is subsequently safe to read from any thread.
                    CLASS.unwrap()
                }
            }
        }

        impl $crate::FromIBinder for dyn $interface {
            fn try_from(mut ibinder: $crate::SpIBinder) -> std::result::Result<$crate::Strong<dyn $interface>, $crate::StatusCode> {
                use $crate::binder_impl::AssociateClass;

                let existing_class = ibinder.get_class();
                if let Some(class) = existing_class {
                    if class != <$native as $crate::binder_impl::Remotable>::get_class() &&
                        class.get_descriptor() == <$native as $crate::binder_impl::Remotable>::get_descriptor()
                    {
                        // The binder object's descriptor string matches what we
                        // expect. We still need to treat this local or already
                        // associated object as remote, because we can't cast it
                        // into a Rust service object without a matching class
                        // pointer.
                        return Ok($crate::Strong::new(Box::new(<$proxy as $crate::binder_impl::Proxy>::from_binder(ibinder)?)));
                    }
                }

                if ibinder.associate_class(<$native as $crate::binder_impl::Remotable>::get_class()) {
                    let service: std::result::Result<$crate::binder_impl::Binder<$native>, $crate::StatusCode> =
                        std::convert::TryFrom::try_from(ibinder.clone());
                    if let Ok(service) = service {
                        // We were able to associate with our expected class and
                        // the service is local.
                        return Ok($crate::Strong::new(Box::new(service)));
                    } else {
                        // Service is remote
                        return Ok($crate::Strong::new(Box::new(<$proxy as $crate::binder_impl::Proxy>::from_binder(ibinder)?)));
                    }
                }

                Err($crate::StatusCode::BAD_TYPE.into())
            }
        }

        impl $crate::binder_impl::Serialize for dyn $interface + '_
        where
            dyn $interface: $crate::Interface
        {
            fn serialize(&self, parcel: &mut $crate::binder_impl::BorrowedParcel<'_>) -> std::result::Result<(), $crate::StatusCode> {
                let binder = $crate::Interface::as_binder(self);
                parcel.write(&binder)
            }
        }

        impl $crate::binder_impl::SerializeOption for dyn $interface + '_ {
            fn serialize_option(this: Option<&Self>, parcel: &mut $crate::binder_impl::BorrowedParcel<'_>) -> std::result::Result<(), $crate::StatusCode> {
                parcel.write(&this.map($crate::Interface::as_binder))
            }
        }

        impl std::fmt::Debug for dyn $interface + '_ {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.pad(stringify!($interface))
            }
        }

        /// Convert a &dyn $interface to Strong<dyn $interface>
        impl std::borrow::ToOwned for dyn $interface {
            type Owned = $crate::Strong<dyn $interface>;
            fn to_owned(&self) -> Self::Owned {
                self.as_binder().into_interface()
                    .expect(concat!("Error cloning interface ", stringify!($interface)))
            }
        }

        $(
        // Async interface trait implementations.
        impl<P: $crate::BinderAsyncPool> $crate::FromIBinder for dyn $async_interface<P> {
            fn try_from(mut ibinder: $crate::SpIBinder) -> std::result::Result<$crate::Strong<dyn $async_interface<P>>, $crate::StatusCode> {
                use $crate::binder_impl::AssociateClass;

                let existing_class = ibinder.get_class();
                if let Some(class) = existing_class {
                    if class != <$native as $crate::binder_impl::Remotable>::get_class() &&
                        class.get_descriptor() == <$native as $crate::binder_impl::Remotable>::get_descriptor()
                    {
                        // The binder object's descriptor string matches what we
                        // expect. We still need to treat this local or already
                        // associated object as remote, because we can't cast it
                        // into a Rust service object without a matching class
                        // pointer.
                        return Ok($crate::Strong::new(Box::new(<$proxy as $crate::binder_impl::Proxy>::from_binder(ibinder)?)));
                    }
                }

                if ibinder.associate_class(<$native as $crate::binder_impl::Remotable>::get_class()) {
                    let service: std::result::Result<$crate::binder_impl::Binder<$native>, $crate::StatusCode> =
                        std::convert::TryFrom::try_from(ibinder.clone());
                    if let Ok(service) = service {
                        // We were able to associate with our expected class and
                        // the service is local.
                        todo!()
                        //return Ok($crate::Strong::new(Box::new(service)));
                    } else {
                        // Service is remote
                        return Ok($crate::Strong::new(Box::new(<$proxy as $crate::binder_impl::Proxy>::from_binder(ibinder)?)));
                    }
                }

                Err($crate::StatusCode::BAD_TYPE.into())
            }
        }

        impl<P: $crate::BinderAsyncPool> $crate::binder_impl::Serialize for dyn $async_interface<P> + '_ {
            fn serialize(&self, parcel: &mut $crate::binder_impl::BorrowedParcel<'_>) -> std::result::Result<(), $crate::StatusCode> {
                let binder = $crate::Interface::as_binder(self);
                parcel.write(&binder)
            }
        }

        impl<P: $crate::BinderAsyncPool> $crate::binder_impl::SerializeOption for dyn $async_interface<P> + '_ {
            fn serialize_option(this: Option<&Self>, parcel: &mut $crate::binder_impl::BorrowedParcel<'_>) -> std::result::Result<(), $crate::StatusCode> {
                parcel.write(&this.map($crate::Interface::as_binder))
            }
        }

        impl<P: $crate::BinderAsyncPool> std::fmt::Debug for dyn $async_interface<P> + '_ {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.pad(stringify!($async_interface))
            }
        }

        /// Convert a &dyn $async_interface to Strong<dyn $async_interface>
        impl<P: $crate::BinderAsyncPool> std::borrow::ToOwned for dyn $async_interface<P> {
            type Owned = $crate::Strong<dyn $async_interface<P>>;
            fn to_owned(&self) -> Self::Owned {
                self.as_binder().into_interface()
                    .expect(concat!("Error cloning interface ", stringify!($async_interface)))
            }
        }

        impl<P: $crate::BinderAsyncPool> $crate::binder_impl::ToAsyncInterface<P> for dyn $interface {
            type Target = dyn $async_interface<P>;
        }

        impl<P: $crate::BinderAsyncPool> $crate::binder_impl::ToSyncInterface for dyn $async_interface<P> {
            type Target = dyn $interface;
        }
        )?
    };
}

/// Declare an AIDL enumeration.
///
/// This is mainly used internally by the AIDL compiler.
#[macro_export]
macro_rules! declare_binder_enum {
    {
        $( #[$attr:meta] )*
        $enum:ident : [$backing:ty; $size:expr] {
            $( $( #[$value_attr:meta] )* $name:ident = $value:expr, )*
        }
    } => {
        $( #[$attr] )*
        #[derive(Default, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
        #[allow(missing_docs)]
        pub struct $enum(pub $backing);
        impl $enum {
            $( $( #[$value_attr] )* #[allow(missing_docs)] pub const $name: Self = Self($value); )*

            #[inline(always)]
            #[allow(missing_docs)]
            pub const fn enum_values() -> [Self; $size] {
                [$(Self::$name),*]
            }
        }

        impl std::fmt::Debug for $enum {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.0 {
                    $($value => f.write_str(stringify!($name)),)*
                    _ => f.write_fmt(format_args!("{}", self.0))
                }
            }
        }

        impl $crate::binder_impl::Serialize for $enum {
            fn serialize(&self, parcel: &mut $crate::binder_impl::BorrowedParcel<'_>) -> std::result::Result<(), $crate::StatusCode> {
                parcel.write(&self.0)
            }
        }

        impl $crate::binder_impl::SerializeArray for $enum {
            fn serialize_array(slice: &[Self], parcel: &mut $crate::binder_impl::BorrowedParcel<'_>) -> std::result::Result<(), $crate::StatusCode> {
                let v: Vec<$backing> = slice.iter().map(|x| x.0).collect();
                <$backing as $crate::binder_impl::SerializeArray>::serialize_array(&v[..], parcel)
            }
        }

        impl $crate::binder_impl::Deserialize for $enum {
            type UninitType = Self;
            fn uninit() -> Self::UninitType { Self::UninitType::default() }
            fn from_init(value: Self) -> Self::UninitType { value }

            fn deserialize(parcel: &$crate::binder_impl::BorrowedParcel<'_>) -> std::result::Result<Self, $crate::StatusCode> {
                parcel.read().map(Self)
            }
        }

        impl $crate::binder_impl::DeserializeArray for $enum {
            fn deserialize_array(parcel: &$crate::binder_impl::BorrowedParcel<'_>) -> std::result::Result<Option<Vec<Self>>, $crate::StatusCode> {
                let v: Option<Vec<$backing>> =
                    <$backing as $crate::binder_impl::DeserializeArray>::deserialize_array(parcel)?;
                Ok(v.map(|v| v.into_iter().map(Self).collect()))
            }
        }
    };
}
