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

use crate::binder::{AsNative, FromIBinder, Strong};
use crate::error::{status_result, status_t, Result, Status, StatusCode};
use crate::parcel::Parcel;
use crate::proxy::SpIBinder;
use crate::sys;

use std::convert::TryInto;
use std::ffi::c_void;
use std::os::raw::{c_char, c_ulong};
use std::mem::{self, MaybeUninit};
use std::ptr;
use std::slice;

/// A struct whose instances can be written to a [`Parcel`].
// Might be able to hook this up as a serde backend in the future?
pub trait Serialize {
    /// Serialize this instance into the given [`Parcel`].
    fn serialize(&self, parcel: &mut Parcel) -> Result<()>;
}

/// A struct whose instances can be restored from a [`Parcel`].
// Might be able to hook this up as a serde backend in the future?
pub trait Deserialize: Sized {
    /// Deserialize an instance from the given [`Parcel`].
    fn deserialize(parcel: &Parcel) -> Result<Self>;

    /// Deserialize an instance from the given [`Parcel`] onto the
    /// current object. This operation will overwrite the old value
    /// partially or completely, depending on how much data is available.
    fn deserialize_from(&mut self, parcel: &Parcel) -> Result<()> {
        *self = Self::deserialize(parcel)?;
        Ok(())
    }
}

/// Helper trait for types that can be serialized as arrays.
/// Defaults to calling Serialize::serialize() manually for every element,
/// but can be overridden for custom implementations like `writeByteArray`.
// Until specialization is stabilized in Rust, we need this to be a separate
// trait because it's the only way to have a default implementation for a method.
// We want the default implementation for most types, but an override for
// a few special ones like `readByteArray` for `u8`.
pub trait SerializeArray: Serialize + Sized {
    /// Serialize an array of this type into the given [`Parcel`].
    fn serialize_array(slice: &[Self], parcel: &mut Parcel) -> Result<()> {
        let res = unsafe {
            // Safety: Safe FFI, slice will always be a safe pointer to pass.
            sys::AParcel_writeParcelableArray(
                parcel.as_native_mut(),
                slice.as_ptr() as *const c_void,
                slice.len().try_into().or(Err(StatusCode::BAD_VALUE))?,
                Some(serialize_element::<Self>),
            )
        };
        status_result(res)
    }
}

/// Callback to serialize an element of a generic parcelable array.
///
/// Safety: We are relying on binder_ndk to not overrun our slice. As long as it
/// doesn't provide an index larger than the length of the original slice in
/// serialize_array, this operation is safe. The index provided is zero-based.
unsafe extern "C" fn serialize_element<T: Serialize>(
    parcel: *mut sys::AParcel,
    array: *const c_void,
    index: c_ulong,
) -> status_t {
    // c_ulong and usize are the same, but we need the explicitly sized version
    // so the function signature matches what bindgen generates.
    let index = index as usize;

    let slice: &[T] = slice::from_raw_parts(array.cast(), index+1);

    let mut parcel = match Parcel::borrowed(parcel) {
        None => return StatusCode::UNEXPECTED_NULL as status_t,
        Some(p) => p,
    };

    slice[index].serialize(&mut parcel)
                .err()
                .unwrap_or(StatusCode::OK)
        as status_t
}

/// Helper trait for types that can be deserialized as arrays.
/// Defaults to calling Deserialize::deserialize() manually for every element,
/// but can be overridden for custom implementations like `readByteArray`.
pub trait DeserializeArray: Deserialize {
    /// Deserialize an array of type from the given [`Parcel`].
    fn deserialize_array(parcel: &Parcel) -> Result<Option<Vec<Self>>> {
        let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
        let res = unsafe {
            // Safety: Safe FFI, vec is the correct opaque type expected by
            // allocate_vec and deserialize_element.
            sys::AParcel_readParcelableArray(
                parcel.as_native(),
                &mut vec as *mut _ as *mut c_void,
                Some(allocate_vec::<Self>),
                Some(deserialize_element::<Self>),
            )
        };
        status_result(res)?;
        let vec: Option<Vec<Self>> = unsafe {
            // Safety: We are assuming that the NDK correctly initialized every
            // element of the vector by now, so we know that all the
            // MaybeUninits are now properly initialized. We can transmute from
            // Vec<MaybeUninit<T>> to Vec<T> because MaybeUninit<T> has the same
            // alignment and size as T, so the pointer to the vector allocation
            // will be compatible.
            mem::transmute(vec)
        };
        Ok(vec)
    }
}

/// Callback to deserialize a parcelable element.
///
/// The opaque array data pointer must be a mutable pointer to an
/// `Option<Vec<MaybeUninit<T>>>` with at least enough elements for `index` to be valid
/// (zero-based).
unsafe extern "C" fn deserialize_element<T: Deserialize>(
    parcel: *const sys::AParcel,
    array: *mut c_void,
    index: c_ulong,
) -> status_t {
    // c_ulong and usize are the same, but we need the explicitly sized version
    // so the function signature matches what bindgen generates.
    let index = index as usize;

    let vec = &mut *(array as *mut Option<Vec<MaybeUninit<T>>>);
    let vec = match vec {
        Some(v) => v,
        None => return StatusCode::BAD_INDEX as status_t,
    };

    let parcel = match Parcel::borrowed(parcel as *mut _) {
        None => return StatusCode::UNEXPECTED_NULL as status_t,
        Some(p) => p,
    };
    let element = match parcel.read() {
        Ok(e) => e,
        Err(code) => return code as status_t,
    };
    ptr::write(vec[index].as_mut_ptr(), element);
    StatusCode::OK as status_t
}

/// Helper trait for types that can be nullable when serialized.
// We really need this trait instead of implementing `Serialize for Option<T>`
// because of the Rust orphan rule which prevents us from doing
// `impl Serialize for Option<&dyn IFoo>` for AIDL interfaces.
// Instead we emit `impl SerializeOption for dyn IFoo` which is allowed.
// We also use it to provide a default implementation for AIDL-generated
// parcelables.
pub trait SerializeOption: Serialize {
    /// Serialize an Option of this type into the given [`Parcel`].
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        if let Some(inner) = this {
            parcel.write(&1i32)?;
            parcel.write(inner)
        } else {
            parcel.write(&0i32)
        }
    }
}

/// Helper trait for types that can be nullable when deserialized.
pub trait DeserializeOption: Deserialize {
    /// Deserialize an Option of this type from the given [`Parcel`].
    fn deserialize_option(parcel: &Parcel) -> Result<Option<Self>> {
        let null: i32 = parcel.read()?;
        if null == 0 {
            Ok(None)
        } else {
            parcel.read().map(Some)
        }
    }

    /// Deserialize an Option of this type from the given [`Parcel`] onto the
    /// current object. This operation will overwrite the current value
    /// partially or completely, depending on how much data is available.
    fn deserialize_option_from(this: &mut Option<Self>, parcel: &Parcel) -> Result<()> {
        *this = Self::deserialize_option(parcel)?;
        Ok(())
    }
}

/// Callback to allocate a vector for parcel array read functions.
///
/// This variant is for APIs which use an out buffer pointer.
///
/// # Safety
///
/// The opaque data pointer passed to the array read function must be a mutable
/// pointer to an `Option<Vec<MaybeUninit<T>>>`. `buffer` will be assigned a mutable pointer
/// to the allocated vector data if this function returns true.
unsafe extern "C" fn allocate_vec_with_buffer<T>(
    data: *mut c_void,
    len: i32,
    buffer: *mut *mut T,
) -> bool {
    let res = allocate_vec::<T>(data, len);
    let vec = &mut *(data as *mut Option<Vec<MaybeUninit<T>>>);
    if let Some(new_vec) = vec {
        *buffer = new_vec.as_mut_ptr() as *mut T;
    }
    res
}

/// Callback to allocate a vector for parcel array read functions.
///
/// # Safety
///
/// The opaque data pointer passed to the array read function must be a mutable
/// pointer to an `Option<Vec<MaybeUninit<T>>>`.
unsafe extern "C" fn allocate_vec<T>(
    data: *mut c_void,
    len: i32,
) -> bool {
    let vec = &mut *(data as *mut Option<Vec<MaybeUninit<T>>>);
    if len < 0 {
        *vec = None;
        return true;
    }
    let mut new_vec: Vec<MaybeUninit<T>> = Vec::with_capacity(len as usize);

    // Safety: We are filling the vector with uninitialized data here, but this
    // is safe because the vector contains MaybeUninit elements which can be
    // uninitialized. We're putting off the actual unsafe bit, transmuting the
    // vector to a Vec<T> until the contents are initialized.
    new_vec.set_len(len as usize);

    ptr::write(vec, Some(new_vec));
    true
}


macro_rules! parcelable_primitives {
    {
        $(
            impl $trait:ident for $ty:ty = $fn:path;
        )*
    } => {
        $(impl_parcelable!{$trait, $ty, $fn})*
    };
}

macro_rules! impl_parcelable {
    {Serialize, $ty:ty, $write_fn:path} => {
        impl Serialize for $ty {
            fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
                unsafe {
                    // Safety: `Parcel` always contains a valid pointer to an
                    // `AParcel`, and any `$ty` literal value is safe to pass to
                    // `$write_fn`.
                    status_result($write_fn(parcel.as_native_mut(), *self))
                }
            }
        }
    };

    {Deserialize, $ty:ty, $read_fn:path} => {
        impl Deserialize for $ty {
            fn deserialize(parcel: &Parcel) -> Result<Self> {
                let mut val = Self::default();
                unsafe {
                    // Safety: `Parcel` always contains a valid pointer to an
                    // `AParcel`. We pass a valid, mutable pointer to `val`, a
                    // literal of type `$ty`, and `$read_fn` will write the
                    // value read into `val` if successful
                    status_result($read_fn(parcel.as_native(), &mut val))?
                };
                Ok(val)
            }
        }
    };

    {SerializeArray, $ty:ty, $write_array_fn:path} => {
        impl SerializeArray for $ty {
            fn serialize_array(slice: &[Self], parcel: &mut Parcel) -> Result<()> {
                let status = unsafe {
                    // Safety: `Parcel` always contains a valid pointer to an
                    // `AParcel`. If the slice is > 0 length, `slice.as_ptr()`
                    // will be a valid pointer to an array of elements of type
                    // `$ty`. If the slice length is 0, `slice.as_ptr()` may be
                    // dangling, but this is safe since the pointer is not
                    // dereferenced if the length parameter is 0.
                    $write_array_fn(
                        parcel.as_native_mut(),
                        slice.as_ptr(),
                        slice
                            .len()
                            .try_into()
                            .or(Err(StatusCode::BAD_VALUE))?,
                    )
                };
                status_result(status)
            }
        }
    };

    {DeserializeArray, $ty:ty, $read_array_fn:path} => {
        impl DeserializeArray for $ty {
            fn deserialize_array(parcel: &Parcel) -> Result<Option<Vec<Self>>> {
                let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
                let status = unsafe {
                    // Safety: `Parcel` always contains a valid pointer to an
                    // `AParcel`. `allocate_vec<T>` expects the opaque pointer to
                    // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
                    // correct for it.
                    $read_array_fn(
                        parcel.as_native(),
                        &mut vec as *mut _ as *mut c_void,
                        Some(allocate_vec_with_buffer),
                    )
                };
                status_result(status)?;
                let vec: Option<Vec<Self>> = unsafe {
                    // Safety: We are assuming that the NDK correctly
                    // initialized every element of the vector by now, so we
                    // know that all the MaybeUninits are now properly
                    // initialized. We can transmute from Vec<MaybeUninit<T>> to
                    // Vec<T> because MaybeUninit<T> has the same alignment and
                    // size as T, so the pointer to the vector allocation will
                    // be compatible.
                    mem::transmute(vec)
                };
                Ok(vec)
            }
        }
    };
}

parcelable_primitives! {
    impl Serialize for bool = sys::AParcel_writeBool;
    impl Deserialize for bool = sys::AParcel_readBool;

    // This is only safe because `Option<Vec<u8>>` is interchangeable with
    // `Option<Vec<i8>>` (what the allocator function actually allocates.
    impl DeserializeArray for u8 = sys::AParcel_readByteArray;

    impl Serialize for i8 = sys::AParcel_writeByte;
    impl Deserialize for i8 = sys::AParcel_readByte;
    impl SerializeArray for i8 = sys::AParcel_writeByteArray;
    impl DeserializeArray for i8 = sys::AParcel_readByteArray;

    impl Serialize for u16 = sys::AParcel_writeChar;
    impl Deserialize for u16 = sys::AParcel_readChar;
    impl SerializeArray for u16 = sys::AParcel_writeCharArray;
    impl DeserializeArray for u16 = sys::AParcel_readCharArray;

    // This is only safe because `Option<Vec<i16>>` is interchangeable with
    // `Option<Vec<u16>>` (what the allocator function actually allocates.
    impl DeserializeArray for i16 = sys::AParcel_readCharArray;

    impl Serialize for u32 = sys::AParcel_writeUint32;
    impl Deserialize for u32 = sys::AParcel_readUint32;
    impl SerializeArray for u32 = sys::AParcel_writeUint32Array;
    impl DeserializeArray for u32 = sys::AParcel_readUint32Array;

    impl Serialize for i32 = sys::AParcel_writeInt32;
    impl Deserialize for i32 = sys::AParcel_readInt32;
    impl SerializeArray for i32 = sys::AParcel_writeInt32Array;
    impl DeserializeArray for i32 = sys::AParcel_readInt32Array;

    impl Serialize for u64 = sys::AParcel_writeUint64;
    impl Deserialize for u64 = sys::AParcel_readUint64;
    impl SerializeArray for u64 = sys::AParcel_writeUint64Array;
    impl DeserializeArray for u64 = sys::AParcel_readUint64Array;

    impl Serialize for i64 = sys::AParcel_writeInt64;
    impl Deserialize for i64 = sys::AParcel_readInt64;
    impl SerializeArray for i64 = sys::AParcel_writeInt64Array;
    impl DeserializeArray for i64 = sys::AParcel_readInt64Array;

    impl Serialize for f32 = sys::AParcel_writeFloat;
    impl Deserialize for f32 = sys::AParcel_readFloat;
    impl SerializeArray for f32 = sys::AParcel_writeFloatArray;
    impl DeserializeArray for f32 = sys::AParcel_readFloatArray;

    impl Serialize for f64 = sys::AParcel_writeDouble;
    impl Deserialize for f64 = sys::AParcel_readDouble;
    impl SerializeArray for f64 = sys::AParcel_writeDoubleArray;
    impl DeserializeArray for f64 = sys::AParcel_readDoubleArray;
}

impl SerializeArray for bool {}
impl DeserializeArray for bool {}

impl Serialize for u8 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        (*self as i8).serialize(parcel)
    }
}

impl Deserialize for u8 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        i8::deserialize(parcel).map(|v| v as u8)
    }
}

impl SerializeArray for u8 {
    fn serialize_array(slice: &[Self], parcel: &mut Parcel) -> Result<()> {
        let status = unsafe {
            // Safety: `Parcel` always contains a valid pointer to an
            // `AParcel`. If the slice is > 0 length, `slice.as_ptr()` will be a
            // valid pointer to an array of elements of type `$ty`. If the slice
            // length is 0, `slice.as_ptr()` may be dangling, but this is safe
            // since the pointer is not dereferenced if the length parameter is
            // 0.
            sys::AParcel_writeByteArray(
                parcel.as_native_mut(),
                slice.as_ptr() as *const i8,
                slice.len().try_into().or(Err(StatusCode::BAD_VALUE))?,
            )
        };
        status_result(status)
    }
}

impl Serialize for i16 {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        (*self as u16).serialize(parcel)
    }
}

impl Deserialize for i16 {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        u16::deserialize(parcel).map(|v| v as i16)
    }
}

impl SerializeArray for i16 {
    fn serialize_array(slice: &[Self], parcel: &mut Parcel) -> Result<()> {
        let status = unsafe {
            // Safety: `Parcel` always contains a valid pointer to an
            // `AParcel`. If the slice is > 0 length, `slice.as_ptr()` will be a
            // valid pointer to an array of elements of type `$ty`. If the slice
            // length is 0, `slice.as_ptr()` may be dangling, but this is safe
            // since the pointer is not dereferenced if the length parameter is
            // 0.
            sys::AParcel_writeCharArray(
                parcel.as_native_mut(),
                slice.as_ptr() as *const u16,
                slice.len().try_into().or(Err(StatusCode::BAD_VALUE))?,
            )
        };
        status_result(status)
    }
}

impl SerializeOption for str {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        match this {
            None => unsafe {
                // Safety: `Parcel` always contains a valid pointer to an
                // `AParcel`. If the string pointer is null,
                // `AParcel_writeString` requires that the length is -1 to
                // indicate that we want to serialize a null string.
                status_result(sys::AParcel_writeString(
                    parcel.as_native_mut(),
                    ptr::null(),
                    -1,
                ))
            },
            Some(s) => unsafe {
                // Safety: `Parcel` always contains a valid pointer to an
                // `AParcel`. `AParcel_writeString` assumes that we pass a utf-8
                // string pointer of `length` bytes, which is what str in Rust
                // is. The docstring for `AParcel_writeString` says that the
                // string input should be null-terminated, but it doesn't
                // actually rely on that fact in the code. If this ever becomes
                // necessary, we will need to null-terminate the str buffer
                // before sending it.
                status_result(sys::AParcel_writeString(
                    parcel.as_native_mut(),
                    s.as_ptr() as *const c_char,
                    s.as_bytes()
                        .len()
                        .try_into()
                        .or(Err(StatusCode::BAD_VALUE))?,
                ))
            },
        }
    }
}

impl SerializeArray for Option<&str> {}

impl Serialize for str {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        Some(self).serialize(parcel)
    }
}

impl SerializeArray for &str {}

impl Serialize for String {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        Some(self.as_str()).serialize(parcel)
    }
}

impl SerializeArray for String {}

impl SerializeOption for String {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(this.map(String::as_str), parcel)
    }
}

impl SerializeArray for Option<String> {}

impl Deserialize for Option<String> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let mut vec: Option<Vec<u8>> = None;
        let status = unsafe {
            // Safety: `Parcel` always contains a valid pointer to an `AParcel`.
            // `Option<Vec<u8>>` is equivalent to the expected `Option<Vec<i8>>`
            // for `allocate_vec`, so `vec` is safe to pass as the opaque data
            // pointer on platforms where char is signed.
            sys::AParcel_readString(
                parcel.as_native(),
                &mut vec as *mut _ as *mut c_void,
                Some(allocate_vec_with_buffer),
            )
        };

        status_result(status)?;
        vec.map(|mut s| {
            // The vector includes a null-terminator and we don't want the
            // string to be null-terminated for Rust.
            s.pop();
            String::from_utf8(s).or(Err(StatusCode::BAD_VALUE))
        })
        .transpose()
    }
}

impl DeserializeArray for Option<String> {}

impl Deserialize for String {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        Deserialize::deserialize(parcel)
            .transpose()
            .unwrap_or(Err(StatusCode::UNEXPECTED_NULL))
    }
}

impl DeserializeArray for String {}

impl<T: SerializeArray> Serialize for [T] {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        SerializeArray::serialize_array(self, parcel)
    }
}

impl<T: SerializeArray> Serialize for Vec<T> {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        SerializeArray::serialize_array(&self[..], parcel)
    }
}

impl<T: SerializeArray> SerializeOption for [T] {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        if let Some(v) = this {
            SerializeArray::serialize_array(v, parcel)
        } else {
            parcel.write(&-1i32)
        }
    }
}

impl<T: SerializeArray> SerializeOption for Vec<T> {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(this.map(Vec::as_slice), parcel)
    }
}

impl<T: DeserializeArray> Deserialize for Vec<T> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        DeserializeArray::deserialize_array(parcel)
            .transpose()
            .unwrap_or(Err(StatusCode::UNEXPECTED_NULL))
    }
}

impl<T: DeserializeArray> DeserializeOption for Vec<T> {
    fn deserialize_option(parcel: &Parcel) -> Result<Option<Self>> {
        DeserializeArray::deserialize_array(parcel)
    }
}

impl Serialize for Status {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        unsafe {
            // Safety: `Parcel` always contains a valid pointer to an `AParcel`
            // and `Status` always contains a valid pointer to an `AStatus`, so
            // both parameters are valid and safe. This call does not take
            // ownership of either of its parameters.
            status_result(sys::AParcel_writeStatusHeader(
                parcel.as_native_mut(),
                self.as_native(),
            ))
        }
    }
}

impl Deserialize for Status {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let mut status_ptr = ptr::null_mut();
        let ret_status = unsafe {
            // Safety: `Parcel` always contains a valid pointer to an
            // `AParcel`. We pass a mutable out pointer which will be
            // assigned a valid `AStatus` pointer if the function returns
            // status OK. This function passes ownership of the status
            // pointer to the caller, if it was assigned.
            sys::AParcel_readStatusHeader(parcel.as_native(), &mut status_ptr)
        };
        status_result(ret_status)?;
        Ok(unsafe {
            // Safety: At this point, the return status of the read call was ok,
            // so we know that `status_ptr` is a valid, owned pointer to an
            // `AStatus`, from which we can safely construct a `Status` object.
            Status::from_ptr(status_ptr)
        })
    }
}

impl<T: Serialize + FromIBinder + ?Sized> Serialize for Strong<T> {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        Serialize::serialize(&**self, parcel)
    }
}

impl<T: SerializeOption + FromIBinder + ?Sized> SerializeOption for Strong<T> {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(this.map(|b| &**b), parcel)
    }
}

impl<T: FromIBinder + ?Sized> Deserialize for Strong<T> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        let ibinder: SpIBinder = parcel.read()?;
        FromIBinder::try_from(ibinder)
    }
}

impl<T: FromIBinder + ?Sized> DeserializeOption for Strong<T> {
    fn deserialize_option(parcel: &Parcel) -> Result<Option<Self>> {
        let ibinder: Option<SpIBinder> = parcel.read()?;
        ibinder.map(FromIBinder::try_from).transpose()
    }
}

// We need these to support Option<&T> for all T
impl<T: Serialize + ?Sized> Serialize for &T {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        Serialize::serialize(*self, parcel)
    }
}

impl<T: SerializeOption + ?Sized> SerializeOption for &T {
    fn serialize_option(this: Option<&Self>, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(this.copied(), parcel)
    }
}

impl<T: SerializeOption> Serialize for Option<T> {
    fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
        SerializeOption::serialize_option(self.as_ref(), parcel)
    }
}

impl<T: DeserializeOption> Deserialize for Option<T> {
    fn deserialize(parcel: &Parcel) -> Result<Self> {
        DeserializeOption::deserialize_option(parcel)
    }

    fn deserialize_from(&mut self, parcel: &Parcel) -> Result<()> {
        DeserializeOption::deserialize_option_from(self, parcel)
    }
}

/// Implement `Deserialize` trait and friends for a parcelable
///
/// This is an internal macro used by the AIDL compiler to implement
/// `Deserialize`, `DeserializeArray` and `DeserializeOption` for
/// structured parcelables. The target type must implement a
/// `deserialize_parcelable` method with the following signature:
/// ```no_run
/// fn deserialize_parcelable(
///     &mut self,
///     parcel: &binder::parcel::Parcelable,
/// ) -> binder::Result<()> {
///     // ...
/// }
/// ```
#[macro_export]
macro_rules! impl_deserialize_for_parcelable {
    ($parcelable:ident) => {
        impl $crate::parcel::Deserialize for $parcelable {
            fn deserialize(
                parcel: &$crate::parcel::Parcel,
            ) -> $crate::Result<Self> {
                $crate::parcel::DeserializeOption::deserialize_option(parcel)
                    .transpose()
                    .unwrap_or(Err($crate::StatusCode::UNEXPECTED_NULL))
            }
            fn deserialize_from(
                &mut self,
                parcel: &$crate::parcel::Parcel,
            ) -> $crate::Result<()> {
                let status: i32 = parcel.read()?;
                if status == 0 {
                    Err($crate::StatusCode::UNEXPECTED_NULL)
                } else {
                    self.deserialize_parcelable(parcel)
                }
            }
        }

        impl $crate::parcel::DeserializeArray for $parcelable {}

        impl $crate::parcel::DeserializeOption for $parcelable {
            fn deserialize_option(
                parcel: &$crate::parcel::Parcel,
            ) -> $crate::Result<Option<Self>> {
                let mut result = None;
                Self::deserialize_option_from(&mut result, parcel)?;
                Ok(result)
            }
            fn deserialize_option_from(
                this: &mut Option<Self>,
                parcel: &$crate::parcel::Parcel,
            ) -> $crate::Result<()> {
                let status: i32 = parcel.read()?;
                if status == 0 {
                    *this = None;
                    Ok(())
                } else {
                    this.get_or_insert_with(Self::default)
                        .deserialize_parcelable(parcel)
                }
            }
        }
    }
}

#[test]
fn test_custom_parcelable() {
    use crate::binder::Interface;
    use crate::native::Binder;
    let mut service = Binder::new(()).as_binder();

    struct Custom(u32, bool, String, Vec<String>);

    impl Serialize for Custom {
        fn serialize(&self, parcel: &mut Parcel) -> Result<()> {
            self.0.serialize(parcel)?;
            self.1.serialize(parcel)?;
            self.2.serialize(parcel)?;
            self.3.serialize(parcel)
        }
    }

    impl Deserialize for Custom {
        fn deserialize(parcel: &Parcel) -> Result<Self> {
            Ok(Custom(
                parcel.read()?,
                parcel.read()?,
                parcel.read()?,
                parcel.read::<Option<Vec<String>>>()?.unwrap(),
            ))
        }
    }

    let string8 = "Custom Parcelable".to_string();

    let s1 = "str1".to_string();
    let s2 = "str2".to_string();
    let s3 = "str3".to_string();

    let strs = vec![s1, s2, s3];

    let custom = Custom(123_456_789, true, string8, strs);

    let mut parcel = Parcel::new_for_test(&mut service).unwrap();
    let start = parcel.get_data_position();

    assert!(custom.serialize(&mut parcel).is_ok());

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let custom2 = Custom::deserialize(&parcel).unwrap();

    assert_eq!(custom2.0, 123_456_789);
    assert!(custom2.1);
    assert_eq!(custom2.2, custom.2);
    assert_eq!(custom2.3, custom.3);
}

#[test]
#[allow(clippy::excessive_precision)]
fn test_slice_parcelables() {
    use crate::binder::Interface;
    use crate::native::Binder;
    let mut service = Binder::new(()).as_binder();

    let bools = [true, false, false, true];

    let mut parcel = Parcel::new_for_test(&mut service).unwrap();
    let start = parcel.get_data_position();

    assert!(bools.serialize(&mut parcel).is_ok());

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4);
    assert_eq!(parcel.read::<u32>().unwrap(), 1);
    assert_eq!(parcel.read::<u32>().unwrap(), 0);
    assert_eq!(parcel.read::<u32>().unwrap(), 0);
    assert_eq!(parcel.read::<u32>().unwrap(), 1);
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<bool>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [true, false, false, true]);

    let u8s = [101u8, 255, 42, 117];

    let mut parcel = Parcel::new_for_test(&mut service).unwrap();
    let start = parcel.get_data_position();

    assert!(parcel.write(&u8s[..]).is_ok());

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0x752aff65); // bytes
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<u8>::deserialize(&parcel).unwrap();
    assert_eq!(vec, [101, 255, 42, 117]);

    let i8s = [-128i8, 127, 42, -117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert!(parcel.write(&i8s[..]).is_ok());

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0x8b2a7f80); // bytes
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<u8>::deserialize(&parcel).unwrap();
    assert_eq!(vec, [-128i8 as u8, 127, 42, -117i8 as u8]);

    let u16s = [u16::max_value(), 12_345, 42, 117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(u16s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0xffff); // u16::max_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 12345); // 12,345
    assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
    assert_eq!(parcel.read::<u32>().unwrap(), 117); // 117
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<u16>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u16::max_value(), 12_345, 42, 117]);

    let i16s = [i16::max_value(), i16::min_value(), 42, -117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(i16s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0x7fff); // i16::max_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 0x8000); // i16::min_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
    assert_eq!(parcel.read::<u32>().unwrap(), 0xff8b); // -117
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<i16>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i16::max_value(), i16::min_value(), 42, -117]);

    let u32s = [u32::max_value(), 12_345, 42, 117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(u32s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0xffffffff); // u32::max_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 12345); // 12,345
    assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
    assert_eq!(parcel.read::<u32>().unwrap(), 117); // 117
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<u32>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u32::max_value(), 12_345, 42, 117]);

    let i32s = [i32::max_value(), i32::min_value(), 42, -117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(i32s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
    assert_eq!(parcel.read::<u32>().unwrap(), 0x7fffffff); // i32::max_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 0x80000000); // i32::min_value()
    assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
    assert_eq!(parcel.read::<u32>().unwrap(), 0xffffff8b); // -117
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<i32>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i32::max_value(), i32::min_value(), 42, -117]);

    let u64s = [u64::max_value(), 12_345, 42, 117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(u64s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<u64>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [u64::max_value(), 12_345, 42, 117]);

    let i64s = [i64::max_value(), i64::min_value(), 42, -117];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(i64s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<i64>::deserialize(&parcel).unwrap();

    assert_eq!(vec, [i64::max_value(), i64::min_value(), 42, -117]);

    let f32s = [
        std::f32::NAN,
        std::f32::INFINITY,
        1.23456789,
        std::f32::EPSILON,
    ];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(f32s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<f32>::deserialize(&parcel).unwrap();

    // NAN != NAN so we can't use it in the assert_eq:
    assert!(vec[0].is_nan());
    assert_eq!(vec[1..], f32s[1..]);

    let f64s = [
        std::f64::NAN,
        std::f64::INFINITY,
        1.234567890123456789,
        std::f64::EPSILON,
    ];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(f64s.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<f64>::deserialize(&parcel).unwrap();

    // NAN != NAN so we can't use it in the assert_eq:
    assert!(vec[0].is_nan());
    assert_eq!(vec[1..], f64s[1..]);

    let s1 = "Hello, Binder!";
    let s2 = "This is a utf8 string.";
    let s3 = "Some more text here.";
    let s4 = "Embedded nulls \0 \0";

    let strs = [s1, s2, s3, s4];

    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }
    assert!(strs.serialize(&mut parcel).is_ok());
    unsafe {
        assert!(parcel.set_data_position(start).is_ok());
    }

    let vec = Vec::<String>::deserialize(&parcel).unwrap();

    assert_eq!(vec, strs);
}
