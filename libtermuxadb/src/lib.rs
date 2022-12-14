use libc::{
    DIR, dirent, c_char, c_int
};

#[no_mangle]
pub unsafe extern "C" fn termuxadb_opendir(name: *const c_char) -> *mut DIR {
    libc::opendir(name)
}

#[no_mangle]
pub unsafe extern "C" fn termuxadb_closedir(dirp: *mut DIR) -> c_int {
    libc::closedir(dirp)
}

#[no_mangle]
pub unsafe extern "C" fn termuxadb_readdir(dirp: *mut DIR) -> *mut dirent {
    libc::readdir(dirp)
}

#[no_mangle]
pub unsafe extern "C" fn termuxadb_open(path: *const c_char, opts: c_int) -> c_int {
    libc::open(path, opts)
}

#[no_mangle]
pub unsafe extern "C" fn termuxadb_create(path: *const c_char, opts: c_int, mode: c_int) -> c_int {
    libc::open(path, opts, mode)
}

#[no_mangle]
pub unsafe extern "C" fn termuxadb_close(fd: c_int) -> c_int {
    libc::close(fd)
}
