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

use crate::session::FileDescriptorTransportMode;
use binder::{unstable_api::AsNative, SpIBinder};
use binder_rpc_unstable_bindgen::ARpcServer;
use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::os::unix::io::{IntoRawFd, OwnedFd};

foreign_type! {
    type CType = binder_rpc_unstable_bindgen::ARpcServer;
    fn drop = binder_rpc_unstable_bindgen::ARpcServer_free;

    /// A type that represents a foreign instance of RpcServer.
    #[derive(Debug)]
    pub struct RpcServer;
    /// A borrowed RpcServer.
    pub struct RpcServerRef;
}

/// SAFETY - The opaque handle can be cloned freely.
unsafe impl Send for RpcServer {}
/// SAFETY - The underlying C++ RpcServer class is thread-safe.
unsafe impl Sync for RpcServer {}

impl RpcServer {
    /// Creates a binder RPC server, serving the supplied binder service implementation on the given
    /// vsock port. Only connections from the given CID are accepted.
    ///
    // Set `cid` to libc::VMADDR_CID_ANY to accept connections from any client.
    // Set `cid` to libc::VMADDR_CID_LOCAL to only bind to the local vsock interface.
    pub fn new_vsock(mut service: SpIBinder, cid: u32, port: u32) -> Result<RpcServer, Error> {
        let service = service.as_native_mut();

        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        unsafe {
            Self::checked_from_ptr(binder_rpc_unstable_bindgen::ARpcServer_newVsock(
                service, cid, port,
            ))
        }
    }

    /// Creates a binder RPC server, serving the supplied binder service implementation on the given
    /// socket file descriptor. The socket should be bound to an address before calling this
    /// function.
    pub fn new_bound_socket(mut service: SpIBinder, socket_fd: OwnedFd) -> Result<RpcServer, Error> {
        let service = service.as_native_mut();

        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        // The server takes ownership of the socket FD.
        unsafe {
            Self::checked_from_ptr(binder_rpc_unstable_bindgen::ARpcServer_newBoundSocket(
                service, socket_fd.into_raw_fd(),
            ))
        }
    }

    /// Creates a binder RPC server that bootstraps sessions using an existing Unix domain socket
    /// pair, with a given root IBinder object. Callers should create a pair of SOCK_STREAM Unix
    /// domain sockets, pass one to the server and the other to the client. Multiple client session
    /// can be created from the client end of the pair.
    pub fn new_unix_domain_bootstrap(
        mut service: SpIBinder,
        bootstrap_fd: OwnedFd,
    ) -> Result<RpcServer, Error> {
        let service = service.as_native_mut();

        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        // The server takes ownership of the bootstrap FD.
        unsafe {
            Self::checked_from_ptr(binder_rpc_unstable_bindgen::ARpcServer_newUnixDomainBootstrap(
                service,
                bootstrap_fd.into_raw_fd(),
            ))
        }
    }

    /// Creates a binder RPC server, serving the supplied binder service implementation on the given
    /// IP address and port.
    pub fn new_inet(mut service: SpIBinder, address: &str, port: u32) -> Result<RpcServer, Error> {
        let address = match CString::new(address) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Cannot convert {} to CString. Error: {:?}", address, e);
                return Err(Error::from(ErrorKind::InvalidInput));
            }
        };
        let service = service.as_native_mut();

        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        unsafe {
            Self::checked_from_ptr(binder_rpc_unstable_bindgen::ARpcServer_newInet(
                service,
                address.as_ptr(),
                port,
            ))
        }
    }

    unsafe fn checked_from_ptr(ptr: *mut ARpcServer) -> Result<RpcServer, Error> {
        if ptr.is_null() {
            return Err(Error::new(ErrorKind::Other, "Failed to start server"));
        }
        Ok(RpcServer::from_ptr(ptr))
    }
}

impl RpcServerRef {
    /// Sets the list of file descriptor transport modes supported by this server.
    pub fn set_supported_file_descriptor_transport_modes(
        &self,
        modes: &[FileDescriptorTransportMode],
    ) {
        // SAFETY - Does not keep the pointer after returning does, nor does it
        // read past its boundary. Only passes the 'self' pointer as an opaque handle.
        unsafe {
            binder_rpc_unstable_bindgen::ARpcServer_setSupportedFileDescriptorTransportModes(
                self.as_ptr(),
                modes.as_ptr(),
                modes.len(),
            )
        }
    }

    /// Starts a new background thread and calls join(). Returns immediately.
    pub fn start(&self) {
        unsafe { binder_rpc_unstable_bindgen::ARpcServer_start(self.as_ptr()) };
    }

    /// Joins the RpcServer thread. The call blocks until the server terminates.
    /// This must be called from exactly one thread.
    pub fn join(&self) {
        unsafe { binder_rpc_unstable_bindgen::ARpcServer_join(self.as_ptr()) };
    }

    /// Shuts down the running RpcServer. Can be called multiple times and from
    /// multiple threads. Called automatically during drop().
    pub fn shutdown(&self) -> Result<(), Error> {
        if unsafe { binder_rpc_unstable_bindgen::ARpcServer_shutdown(self.as_ptr()) } {
            Ok(())
        } else {
            Err(Error::from(ErrorKind::UnexpectedEof))
        }
    }
}
