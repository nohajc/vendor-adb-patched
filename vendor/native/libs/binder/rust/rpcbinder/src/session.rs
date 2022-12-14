/*
 * Copyright (C) 2022 The Android Open Source Project
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

use binder::unstable_api::new_spibinder;
use binder::{FromIBinder, SpIBinder, StatusCode, Strong};
use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use std::ffi::CString;
use std::os::{
    raw::{c_int, c_void},
    unix::io::{AsRawFd, BorrowedFd, RawFd},
};

pub use binder_rpc_unstable_bindgen::ARpcSession_FileDescriptorTransportMode as FileDescriptorTransportMode;

foreign_type! {
    type CType = binder_rpc_unstable_bindgen::ARpcSession;
    fn drop = binder_rpc_unstable_bindgen::ARpcSession_free;

    /// A type that represents a foreign instance of RpcSession.
    #[derive(Debug)]
    pub struct RpcSession;
    /// A borrowed RpcSession.
    pub struct RpcSessionRef;
}

/// SAFETY - The opaque handle can be cloned freely.
unsafe impl Send for RpcSession {}
/// SAFETY - The underlying C++ RpcSession class is thread-safe.
unsafe impl Sync for RpcSession {}

impl RpcSession {
    /// Allocates a new RpcSession object.
    pub fn new() -> RpcSession {
        // SAFETY - Takes ownership of the returned handle, which has correct refcount.
        unsafe { RpcSession::from_ptr(binder_rpc_unstable_bindgen::ARpcSession_new()) }
    }
}

impl Default for RpcSession {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcSessionRef {
    /// Sets the file descriptor transport mode for this session.
    pub fn set_file_descriptor_transport_mode(&self, mode: FileDescriptorTransportMode) {
        // SAFETY - Only passes the 'self' pointer as an opaque handle.
        unsafe {
            binder_rpc_unstable_bindgen::ARpcSession_setFileDescriptorTransportMode(
                self.as_ptr(),
                mode,
            )
        };
    }

    /// Sets the maximum number of incoming threads.
    pub fn set_max_incoming_threads(&self, threads: usize) {
        // SAFETY - Only passes the 'self' pointer as an opaque handle.
        unsafe {
            binder_rpc_unstable_bindgen::ARpcSession_setMaxIncomingThreads(self.as_ptr(), threads)
        };
    }

    /// Sets the maximum number of outgoing connections.
    pub fn set_max_outgoing_connections(&self, connections: usize) {
        // SAFETY - Only passes the 'self' pointer as an opaque handle.
        unsafe {
            binder_rpc_unstable_bindgen::ARpcSession_setMaxOutgoingConnections(
                self.as_ptr(),
                connections,
            )
        };
    }

    /// Connects to an RPC Binder server over vsock for a particular interface.
    pub fn setup_vsock_client<T: FromIBinder + ?Sized>(
        &self,
        cid: u32,
        port: u32,
    ) -> Result<Strong<T>, StatusCode> {
        // SAFETY: AIBinder returned by ARpcSession_setupVsockClient has correct
        // reference count, and the ownership can safely be taken by new_spibinder.
        let service = unsafe {
            new_spibinder(binder_rpc_unstable_bindgen::ARpcSession_setupVsockClient(
                self.as_ptr(),
                cid,
                port,
            ))
        };
        Self::get_interface(service)
    }

    /// Connects to an RPC Binder server over a names Unix Domain Socket for
    /// a particular interface.
    pub fn setup_unix_domain_client<T: FromIBinder + ?Sized>(
        &self,
        socket_name: &str,
    ) -> Result<Strong<T>, StatusCode> {
        let socket_name = match CString::new(socket_name) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Cannot convert {} to CString. Error: {:?}", socket_name, e);
                return Err(StatusCode::NAME_NOT_FOUND);
            }
        };

        // SAFETY: AIBinder returned by ARpcSession_setupUnixDomainClient has correct
        // reference count, and the ownership can safely be taken by new_spibinder.
        let service = unsafe {
            new_spibinder(binder_rpc_unstable_bindgen::ARpcSession_setupUnixDomainClient(
                self.as_ptr(),
                socket_name.as_ptr(),
            ))
        };
        Self::get_interface(service)
    }

    /// Connects to an RPC Binder server over a bootstrap Unix Domain Socket
    /// for a particular interface.
    pub fn setup_unix_domain_bootstrap_client<T: FromIBinder + ?Sized>(
        &self,
        bootstrap_fd: BorrowedFd,
    ) -> Result<Strong<T>, StatusCode> {
        // SAFETY: ARpcSession_setupUnixDomainBootstrapClient does not take
        // ownership of bootstrap_fd. The returned AIBinder has correct
        // reference count, and the ownership can safely be taken by new_spibinder.
        let service = unsafe {
            new_spibinder(binder_rpc_unstable_bindgen::ARpcSession_setupUnixDomainBootstrapClient(
                self.as_ptr(),
                bootstrap_fd.as_raw_fd(),
            ))
        };
        Self::get_interface(service)
    }

    /// Connects to an RPC Binder server over inet socket at the given address and port.
    pub fn setup_inet_client<T: FromIBinder + ?Sized>(
        &self,
        address: &str,
        port: u32,
    ) -> Result<Strong<T>, StatusCode> {
        let address = match CString::new(address) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Cannot convert {} to CString. Error: {:?}", address, e);
                return Err(StatusCode::BAD_VALUE);
            }
        };

        // SAFETY: AIBinder returned by ARpcSession_setupInet has correct reference
        // count, and the ownership can safely be taken by new_spibinder.
        let service = unsafe {
            new_spibinder(binder_rpc_unstable_bindgen::ARpcSession_setupInet(
                self.as_ptr(),
                address.as_ptr(),
                port,
            ))
        };
        Self::get_interface(service)
    }

    /// Connects to an RPC Binder server, using the given callback to get (and
    /// take ownership of) file descriptors already connected to it.
    pub fn setup_preconnected_client<T: FromIBinder + ?Sized>(
        &self,
        mut request_fd: impl FnMut() -> Option<RawFd>,
    ) -> Result<Strong<T>, StatusCode> {
        // Double reference the factory because trait objects aren't FFI safe.
        let mut request_fd_ref: RequestFd = &mut request_fd;
        let param = &mut request_fd_ref as *mut RequestFd as *mut c_void;

        // SAFETY: AIBinder returned by RpcPreconnectedClient has correct reference count, and the
        // ownership can be safely taken by new_spibinder. RpcPreconnectedClient does not take ownership
        // of param, only passing it to request_fd_wrapper.
        let service = unsafe {
            new_spibinder(binder_rpc_unstable_bindgen::ARpcSession_setupPreconnectedClient(
                self.as_ptr(),
                Some(request_fd_wrapper),
                param,
            ))
        };
        Self::get_interface(service)
    }

    fn get_interface<T: FromIBinder + ?Sized>(
        service: Option<SpIBinder>,
    ) -> Result<Strong<T>, StatusCode> {
        if let Some(service) = service {
            FromIBinder::try_from(service)
        } else {
            Err(StatusCode::NAME_NOT_FOUND)
        }
    }
}

type RequestFd<'a> = &'a mut dyn FnMut() -> Option<RawFd>;

unsafe extern "C" fn request_fd_wrapper(param: *mut c_void) -> c_int {
    // SAFETY: This is only ever called by RpcPreconnectedClient, within the lifetime of the
    // BinderFdFactory reference, with param being a properly aligned non-null pointer to an
    // initialized instance.
    let request_fd_ptr = param as *mut RequestFd;
    let request_fd = request_fd_ptr.as_mut().unwrap();
    request_fd().unwrap_or(-1)
}
