extern crate nix;
extern crate libc;
extern crate ipc_channel;

use ipc_channel::ipc;
use libc::pid_t;
use nix::{fcntl, mount, sched, unistd};
use nix::sys::ptrace::{ptrace, ptrace_setoptions};
use nix::sys::signal::Signal;
use nix::sys::stat;
use nix::sys::syscall;
use nix::sys::wait::{waitpid, WaitStatus, PtraceEvent};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::{env, fs, ptr};
use std::io::Write;
use std::os::unix::io::RawFd;

const PTRACE_O_EXITKILL: ptrace::PtraceOptions = 1 << 20;
const PTRACE_O_TRACESYSGOOD: ptrace::PtraceOptions = 1;

#[allow(unused_must_use)]
fn close_fds(saved_fd: RawFd) {
    for n in 3..1024 {
        if n == saved_fd {
            continue;
        }
        unistd::close(n);
    }
}

fn setup_seccomp() {
    #[repr(C)]
    struct SockFilter(u16, u8, u8, u32);
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    const SECCOMP_MODE_FILTER: libc::c_uint = 2;
    const PR_SET_SECCOMP: libc::c_int = 22;
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

    static MYFILTER: [SockFilter; 8] = [SockFilter(0x20, 0, 0, 4),
                                        SockFilter(0x15, 0, 4, 62 | 0x80000000 | 0x40000000),
                                        SockFilter(0x20, 0, 0, 0),
                                        SockFilter(0x15, 2, 0, 56),
                                        SockFilter(0x15, 1, 0, 57),
                                        SockFilter(0x15, 0, 1, 58),
                                        SockFilter(0x06, 0, 0, 0),
                                        SockFilter(0x06, 0, 0, 0x7fff0000)];
    let myfilter = SockFprog {
        len: 8,
        filter: &MYFILTER[0] as *const _,
    };
    unsafe {
        assert!(libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        assert!(libc::prctl(PR_SET_SECCOMP,
                            SECCOMP_MODE_FILTER,
                            &myfilter as *const _,
                            0,
                            0) == 0);
    }

}

fn exec_inferior(fd: RawFd) -> isize {
    close_fds(fd);
    setup_seccomp();
    ptrace(ptrace::PTRACE_TRACEME, 0, ptr::null_mut(), ptr::null_mut())
        .expect("Failed PTRACE_TRACEME");

    #[allow(non_upper_case_globals)]
    const SYS_execveat: libc::c_long = 322;
    const AT_EMPTY_PATH: libc::c_int = 0x1000;
    unsafe {
        syscall::syscall(SYS_execveat,
                         fd,
                         b"\0",
                         [b"sh\0", ptr::null()].as_ptr(),
                         [ptr::null::<u8>()].as_ptr(),
                         AT_EMPTY_PATH);
    }
    0
}

fn pivot_root() {
    mount::mount::<str, str, str, str>(None, "/tmp", Some("tmpfs"), mount::MsFlags::empty(), None)
        .unwrap();
    unistd::mkdir("/tmp/old_root", stat::Mode::empty()).unwrap();
    unistd::pivot_root("/tmp", "/tmp/old_root").unwrap();
    unistd::chdir("/").unwrap();
    mount::umount2("/old_root", mount::MNT_DETACH).unwrap();
    assert!(unsafe { libc::rmdir(CString::new("/old_root").unwrap().as_ptr()) } == 0);
    mount::mount::<str, str, str, str>(None,
                                       "/",
                                       Some("/"),
                                       mount::MS_BIND | mount::MS_REMOUNT | mount::MS_RDONLY,
                                       None)
        .unwrap();
}

fn drop_caps() {
    #[allow(non_upper_case_globals)]
    const SYS_capset: libc::c_long = 126;
    #[repr(C)]
    struct UserCapHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct UserCapData(u32, u32, u32);

    static HEADER: UserCapHeader = UserCapHeader {
        version: 0x20071026,
        pid: 0,
    };
    static DATA: [UserCapData; 2] = [UserCapData(0, 0, 0), UserCapData(0, 0, 0)];

    unsafe {
        assert!(syscall::syscall(SYS_capset, &HEADER, DATA.as_ptr()) == 0);
    }
}

fn fix_uid_map(euid: libc::uid_t, egid: libc::gid_t) {
    fn write(path: &str, contents: &str) {
        let mut file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }
    write("/proc/self/uid_map", &format!("0 {} 1", euid));
    write("/proc/self/setgroups", "deny");
    write("/proc/self/gid_map", &format!("0 {} 1", egid));
}

fn setup_tracee(sender: &ipc::IpcSender<pid_t>, fd: RawFd) -> isize {
    let mut stack = vec![0u8; 4096];
    let euid = unistd::geteuid();
    let egid = unistd::getegid();

    sched::unshare(sched::CLONE_NEWIPC | sched::CLONE_NEWNET | sched::CLONE_NEWNS |
                   sched::CLONE_NEWPID | sched::CLONE_NEWUTS |
                   sched::CLONE_NEWUSER)
        .unwrap();

    fix_uid_map(euid, egid);
    pivot_root();
    drop_caps();

    let pid = sched::clone(Box::new(move || exec_inferior(fd)),
                           &mut stack,
                           sched::CLONE_PARENT,
                           Some(libc::SIGCHLD))
        .unwrap();
    sender.send(pid).unwrap();
    0
}

fn fork_tracee(fd: RawFd) -> Result<pid_t, nix::Error> {
    let (sender, receiver) = ipc::channel::<pid_t>().unwrap();

    let helper_pid = match unistd::fork()? {
        unistd::ForkResult::Child => {
            setup_tracee(&sender, fd);
            unsafe { libc::_exit(0) }
        }
        unistd::ForkResult::Parent { child } => child,
    };

    let tracee_pid = receiver.recv().unwrap();

    match waitpid(helper_pid, None)? {
        WaitStatus::Exited(pid, code) => {
            assert!(pid == helper_pid);
            assert!(code == 0);
            Ok(tracee_pid)
        }
        _ => {
            panic!("Unexpected signal");
        }
    }
}

fn start(fd: RawFd) -> Result<pid_t, nix::Error> {
    let pid = fork_tracee(fd)?;
    match waitpid(pid, None)? {
        WaitStatus::Stopped(pid2, Signal::SIGTRAP) => {
            assert!(pid == pid2);
        }
        w => panic!("Unexpected result from waitpid: {:?}", w),
    }

    ptrace_setoptions(pid,
                      ptrace::PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD)?;
    Ok(pid)
}

enum SyscallResult {
    Exited(i8),
    Syscall(i64, i64),
}

fn run_until_syscall(pid: pid_t) -> Result<SyscallResult, nix::Error> {
    const RAX: usize = 8 * 10;
    const ORIG_RAX: usize = 8 * 15;

    loop {
        ptrace(ptrace::PTRACE_SYSCALL,
               pid,
               ptr::null_mut(),
               ptr::null_mut())?;
        match waitpid(pid, None)? {
            WaitStatus::Exited(pid2, code) => {
                assert!(pid == pid2);
                return Ok(SyscallResult::Exited(code));
            }
            WaitStatus::Signaled(pid2, Signal::SIGSYS, _) => {
                assert!(pid == pid2);
                return Ok(SyscallResult::Exited(-1));
            }
            WaitStatus::SyscallPtraceEvent(pid2) => {
                assert!(pid == pid2);
                let syscall = ptrace(ptrace::PTRACE_PEEKUSER,
                                     pid,
                                     ORIG_RAX as *mut _,
                                     ptr::null_mut())?;
                let return_value =
                    ptrace(ptrace::PTRACE_PEEKUSER, pid, RAX as *mut _, ptr::null_mut())?;
                return Ok(SyscallResult::Syscall(syscall, return_value));
            }
            WaitStatus::Signaled(pid2, _, _) |
            WaitStatus::Stopped(pid2, _) |
            WaitStatus::StoppedPtraceEvent(pid2, PtraceEvent::Exec) => {
                assert!(pid == pid2);
                continue;
            }
            w => {
                panic!("Unexpected waitpid result: {:?}", w);
            }
        }
    }
}

fn count_files(path: &str) -> usize {
    fs::read_dir(path).unwrap().map(|e| e.unwrap()).count()
}

fn run(fd: RawFd) -> Result<i8, nix::Error> {
    let pid = start(fd)?;
    let path = format!("/proc/{}/fd", pid);
    let mut good = BTreeSet::new();
    let mut last_count = count_files(&path);
    loop {
        let syscall = match run_until_syscall(pid)? {
            SyscallResult::Exited(code) => return Ok(code),
            SyscallResult::Syscall(syscall, return_value) => {
                assert!(return_value == -libc::ENOSYS as i64);
                syscall
            }
        };

        assert!(last_count == count_files(&path));

        match run_until_syscall(pid)? {
            SyscallResult::Exited(code) => return Ok(code),
            SyscallResult::Syscall(syscall2, return_value) => {
                assert!(return_value != -libc::ENOSYS as i64);
                assert!(syscall == syscall2);
            }
        }

        let count = count_files(&path);

        if count != last_count {
            last_count = count;
            if good.insert(syscall) {
                println!("score: {}", good.len() * 5);
                println!("you have: {:?}", good);
            }
        }
    }
}

fn main() {
    let fd = fcntl::open(&*env::args().nth(1).expect("Give me a filename"),
                         fcntl::O_RDONLY | fcntl::O_CLOEXEC,
                         stat::Mode::empty())
        .expect("Could not open file");
    run(fd).unwrap();
}
