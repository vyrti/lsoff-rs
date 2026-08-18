use std::ffi::c_int;
use std::io;
use std::time::Duration;

/// Reactive `kqueue` process exit/exec watcher for macOS.
pub struct ProcessWatcher {
    kq: c_int,
}

impl ProcessWatcher {
    /// Creates a new `kqueue` process lifecycle monitor.
    ///
    /// # Errors
    /// Returns `io::Error` if kqueue creation fails.
    pub fn new() -> io::Result<Self> {
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { kq })
    }

    /// Registers a PID to receive `NOTE_EXIT` / `NOTE_EXEC` events.
    ///
    /// # Errors
    /// Returns `io::Error` if kevent registration fails.
    pub fn watch_pid(&self, pid: i32) -> io::Result<()> {
        let change = libc::kevent {
            ident: pid as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT | libc::NOTE_EXEC,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let ret = unsafe {
            libc::kevent(
                self.kq,
                &change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Waits up to `timeout` for any monitored process to change or exit.
    ///
    /// # Errors
    /// Returns `io::Error` if kevent poll fails.
    pub fn wait_event(&self, timeout: Duration) -> io::Result<bool> {
        let ts = libc::timespec {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_nsec: timeout.subsec_nanos() as libc::c_long,
        };
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::kevent(self.kq, std::ptr::null(), 0, &mut event, 1, &ts) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(err);
        }
        Ok(ret > 0)
    }
}

impl Drop for ProcessWatcher {
    fn drop(&mut self) {
        if self.kq >= 0 {
            unsafe { libc::close(self.kq) };
        }
    }
}
