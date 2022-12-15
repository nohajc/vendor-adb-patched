use std::{
    os::unix::{net::UnixDatagram, prelude::{RawFd, AsRawFd, FromRawFd, OsStrExt}},
    thread, process::{Command, ExitStatus}, time::Duration, io, str, env, sync::Mutex, path::{PathBuf, Path}, collections::HashMap, ffi::OsStr, mem, ptr::null_mut
};

use anyhow::Context;
use libc::{
    DIR, dirent, c_char, c_int, fcntl, F_GETFD, F_SETFD, FD_CLOEXEC, c_uchar, c_ushort, DT_CHR, DT_DIR
};

use nix::{unistd::{lseek, Whence}, sys::stat::fstat, fcntl::readlink};
use once_cell::sync::Lazy;
use rand::Rng;
use rusb::{constants::LIBUSB_OPTION_NO_DEVICE_DISCOVERY, UsbContext};
use sendfd::{SendWithFd, RecvWithFd};
use which::which;

use log::{debug, info, error};

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

#[no_mangle]
pub unsafe extern "C" fn termuxadb_start() {
    env_logger::init();

    thread::spawn(|| {
        info!("Oh hi, termux-adb!");
        if let Err(e) = start() {
            error!("{}", e);
            // std::process::exit(1);
        }
    });
}

#[no_mangle]
pub extern "C" fn termuxadb_sendfd() -> bool {
    match (env::var("TERMUX_USB_DEV"), env::var("TERMUX_USB_FD"), env::var("TERMUX_ADB_SOCK_FD")) {
        (Ok(termux_usb_dev), Ok(termux_usb_fd), Ok(sock_send_fd)) => {
            if let Err(e) = sendfd_to_adb(&termux_usb_dev, &termux_usb_fd, &sock_send_fd) {
                error!("{}", e)
            }
            true
        }
        _ => false
    }
}

fn sendfd_to_adb(termux_usb_dev: &str, termux_usb_fd: &str, sock_send_fd: &str) -> anyhow::Result<()> {
    let socket = unsafe{ UnixDatagram::from_raw_fd(sock_send_fd.parse()?) };
    // send termux_usb_dev and termux_usb_fd to adb-hooks
    match socket.send_with_fd(termux_usb_dev.as_bytes(), &[termux_usb_fd.parse()?]) {
        Ok(_) => {
            info!("found {}, sending fd {} to adb", &termux_usb_dev, &termux_usb_fd);
        }
        Err(e) => {
            error!("error sending usb fd to adb-hooks: {}", e);
        }
    }
    Ok(())
}

const REQUIRED_CMDS: [&str; 1] = ["termux-usb"];

fn check_dependencies() -> anyhow::Result<()> {
    for dep in REQUIRED_CMDS {
        _ = which(dep).context(format!("error: {} command not found", dep))?;
    }
    Ok(())
}

fn clear_cloexec_flag(socket: &UnixDatagram) -> RawFd {
    let sock_fd = socket.as_raw_fd();
    unsafe {
        let flags = fcntl(sock_fd, F_GETFD);
        fcntl(sock_fd, F_SETFD, flags & !FD_CLOEXEC);
    }
    sock_fd
}

fn get_termux_usb_list() -> Vec<String> {
    if let Ok(out) = Command::new("termux-usb").arg("-l").output() {
        if let Ok(stdout) = str::from_utf8(&out.stdout) {
            if let Ok(lst) = serde_json::from_str(stdout) {
                return lst;
            }
        }
    }
    vec![]
}

fn run_under_termux_usb(usb_dev_path: &str, sock_send_fd: RawFd) -> io::Result<ExitStatus> {
    let mut cmd = Command::new("termux-usb");

    cmd.env("TERMUX_USB_DEV", usb_dev_path)
        .arg("-e").arg("adb")
        .args(["-E", "-r", usb_dev_path]);

    cmd.env("TERMUX_ADB_SOCK_FD", sock_send_fd.to_string());
    return cmd.status();
}

fn scan_for_usb_devices(socket: UnixDatagram) {
    let mut last_usb_list = vec![];

    loop {
        let usb_dev_list = get_termux_usb_list();
        let usb_dev_path = usb_dev_list.iter().next();

        if let Some(usb_dev_path) = usb_dev_path {
            if last_usb_list.iter().find(|&dev| dev == usb_dev_path) == None {
                info!("new device connected: {}", usb_dev_path);
                _ = run_under_termux_usb(&usb_dev_path, socket.as_raw_fd());
            }
        } else if last_usb_list.len() > 0 {
            info!("all devices disconnected");
        }
        last_usb_list = usb_dev_list;
        thread::sleep(Duration::from_millis(2000));
    }
}

fn start() -> anyhow::Result<()> {
    check_dependencies()?;

    let (sock_send, sock_recv) =
        UnixDatagram::pair().context("could not create socket pair")?;

    // we need to unset FD_CLOEXEC flag so that the socket
    // can be passed to adb when it's run as child process
    _ = clear_cloexec_flag(&sock_send);

    thread::spawn(move || {
        if let Err(e) = start_socket_listener(sock_recv) {
            error!("socket listener error: {}", e);
        }
    });

    scan_for_usb_devices(sock_send);

    Ok(())
}

#[derive(Clone)]
struct UsbSerial {
    number: String,
    path: PathBuf,
}

static TERMUX_USB_DEV: Mutex<Option<PathBuf>> = Mutex::new(None);
static TERMUX_USB_FD: Mutex<Option<RawFd>> = Mutex::new(None);
static TERMUX_USB_SERIAL: Mutex<Option<UsbSerial>> = Mutex::new(None);

fn start_socket_listener(socket: UnixDatagram) -> anyhow::Result<()> {
    info!("listening on socket");
    _ = socket.set_read_timeout(None);
    loop {
        let mut buf = vec![0; 256];
        let mut fds = vec![0; 1];
        match socket.recv_with_fd(buf.as_mut_slice(), fds.as_mut_slice()) {
            Ok((_, 0)) => {
                error!("received message without usb fd");
            }
            Ok((size, _)) => {
                let usb_dev_path = PathBuf::from(String::from_utf8_lossy(&buf[0..size]).as_ref());
                let usb_fd = fds[0];
                // use the received info as TERMUX_USB_DEV and TERMUX_USB_FD
                info!("received message (size={}) with fd={}: {}", size, usb_fd, usb_dev_path.display());

                update_dir_map(&mut DIR_MAP.lock().unwrap(), &usb_dev_path);
                *TERMUX_USB_DEV.lock().unwrap() = Some(usb_dev_path);
                *TERMUX_USB_FD.lock().unwrap() = Some(usb_fd);
                *TERMUX_USB_SERIAL.lock().unwrap() = log_err_and_convert(init_libusb_device_serial(usb_fd));
            }
            Err(e) => {
                error!("message receive error: {}", e);
            }
        }
    }
}

// our directory structure will always be flat
// so we can have just one dirent per DirStream
#[derive(Clone)]
struct DirStream {
    pos: i32,
    entry: dirent,
}

static DIR_MAP: Lazy<Mutex<HashMap<PathBuf, DirStream>>> = Lazy::new(|| Mutex::new(HashMap::new()));

const BASE_DIR_ORIG: &str = "/dev/bus/usb";

trait NameSetter {
    fn set_name(&mut self, name: &OsStr);
}

impl NameSetter for dirent {
    fn set_name(&mut self, name: &OsStr) {
        for (i, j) in self.d_name.iter_mut().zip(
            name.as_bytes().iter().chain([0].iter())
        ) {
            *i = *j as c_char;
        }
    }
}

fn dirent_new(off: i64, typ: c_uchar, name: &OsStr) -> dirent {
    let mut rng = rand::thread_rng();
    let mut entry = dirent {
        d_ino: rng.gen(),
        d_off: off,
        d_reclen: mem::size_of::<dirent>() as c_ushort,
        d_type: typ,
        d_name: [0; 256],
    };
    entry.set_name(name);

    entry
}

fn update_dir_map(dir_map: &mut HashMap<PathBuf, DirStream>, usb_dev_path: &Path) {
    dir_map.clear();

    if let Some(usb_dev_name) = usb_dev_path.file_name() {
        let mut last_entry = dirent_new(
            0, DT_CHR, usb_dev_name
        );
        let mut current_dir = usb_dev_path.to_owned();

        while current_dir.pop() {
            dir_map.insert(current_dir.clone(), DirStream{
                pos: 0,
                entry: last_entry.clone(),
            });
            last_entry = dirent_new(
                0, DT_DIR, current_dir.file_name().unwrap()
            );

            if current_dir.as_os_str() == BASE_DIR_ORIG {
                break;
            }
        }
    }
}

fn log_err_and_convert<T>(r: anyhow::Result<T>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            error!("{}", e);
            None
        }
    }
}

fn init_libusb_device_serial(usb_fd: c_int) -> anyhow::Result<UsbSerial> {
    debug!("calling libusb_set_option");
    unsafe{ rusb::ffi::libusb_set_option(null_mut(), LIBUSB_OPTION_NO_DEVICE_DISCOVERY) };

    lseek(usb_fd, 0, Whence::SeekSet)
        .with_context(|| format!("error seeking fd: {}", usb_fd))?;

    let ctx = rusb::Context::new().context("libusb_init error")?;

    debug!("opening device from {}", usb_fd);
    let usb_handle = unsafe{
        ctx.open_device_with_fd(usb_fd).context("error opening device")
    }?;

    debug!("getting device from handle");
    let usb_dev = usb_handle.device();

    debug!("requesting device descriptor");
    let usb_dev_desc = usb_dev.device_descriptor()
        .context("error getting device descriptor")?;

    let vid = usb_dev_desc.vendor_id();
    let pid = usb_dev_desc.product_id();
    let iser = usb_dev_desc.serial_number_string_index();
    debug!("device descriptor: vid={}, pid={}, iSerial={}", vid, pid, iser.unwrap_or(0));

    let timeout = Duration::from_secs(1);
    let languages = usb_handle.read_languages(timeout)
        .context("error getting supported languages for reading string descriptors")?;

    let serial_number = usb_handle.read_serial_number_string(
        languages[0], &usb_dev_desc, timeout
    ).context("error reading serial number of the device")?;

    let st = fstat(usb_fd).context("error: could not stat TERMUX_USB_FD")?;
    let dev_path_link = format!("/sys/dev/char/{}:{}", major(st.st_rdev), minor(st.st_rdev));

    let dev_path = PathBuf::from(readlink(
    &PathBuf::from(&dev_path_link))
        .context(format!("error: could not resolve symlink {}", &dev_path_link)
    )?);

    let mut dev_serial_path = PathBuf::from("/sys/bus/usb/devices");

    dev_serial_path.push(dev_path.file_name().context("error: could not get device path")?);
    dev_serial_path.push("serial");

    info!("device serial path: {}", dev_serial_path.display());

    Ok(UsbSerial{ number: serial_number, path: dev_serial_path })
}


pub const fn major(dev: u64) -> u64 {
    ((dev >> 32) & 0xffff_f000) |
    ((dev >>  8) & 0x0000_0fff)
}

pub const fn minor(dev: u64) -> u64 {
    ((dev >> 12) & 0xffff_ff00) |
    ((dev      ) & 0x0000_00ff)
}