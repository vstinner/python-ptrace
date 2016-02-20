# From Linux kernel source code
#    include/linux/syscalls.h
#    arch/i386/kernel/syscall_table.S
#    arch/um/include/sysdep-i386/syscalls.h
#    arch/um/sys-i386/sys_call_table.S

ALIASES = {
    "mmap": ("mmap2",),
    "break": ("brk",),
    "exit": ("exit_group",),
    "fcntl": ("fcntl64",),
    "getcwd": ("__getcwd",),
}

# Name of arguments containing a filename or a path
FILENAME_ARGUMENTS = set(
    ("filename", "pathname", "oldpath", "newpath", "target", "linkpath"))

DIRFD_ARGUMENTS = set(("dirfd", "olddirfd", "newdirfd"))

SYSCALL_PROTOTYPES = {
    "quotactl": ("long", (
        ("unsigned int", "cmd"),
        ("const char *", "special"),
        ("qid_t", "id"),
        ("void *", "addr"),
    )),
    "time": ("long", (
        ("time_t *", "tloc"),
    )),
    "stime": ("long", (
        ("time_t *", "tptr"),
    )),
    "gettimeofday": ("long", (
        ("struct timeval *", "tv"),
        ("struct timezone *", "tz"),
    )),
    "settimeofday": ("long", (
        ("struct timeval *", "tv"),
        ("struct timezone *", "tz"),
    )),
    "adjtimex": ("long", (
        ("struct timex *", "txc_p"),
    )),
    "times": ("long", (
        ("struct tms *", "tbuf"),
    )),
    "gettid": ("long", (
    )),
    "nanosleep": ("long", (
        ("struct timespec *", "rqtp"),
        ("struct timespec *", "rmtp"),
    )),
    "alarm": ("long", (
        ("unsigned int", "seconds"),
    )),
    "getpid": ("long", (
    )),
    "getppid": ("long", (
    )),
    "getuid": ("long", (
    )),
    "geteuid": ("long", (
    )),
    "getgid": ("long", (
    )),
    "getegid": ("long", (
    )),
    "getresuid": ("long", (
        ("uid_t *", "ruid"),
        ("uid_t *", "euid"),
        ("uid_t *", "suid"),
    )),
    "getresgid": ("long", (
        ("gid_t *", "rgid"),
        ("gid_t *", "egid"),
        ("gid_t *", "sgid"),
    )),
    "getpgid": ("long", (
        ("pid_t", "pid"),
    )),
    "getpgrp": ("long", (
    )),
    "getsid": ("long", (
        ("pid_t", "pid"),
    )),
    "getgroups": ("long", (
        ("int", "gidsetsize"),
        ("gid_t *", "grouplist"),
    )),
    "setregid": ("long", (
        ("gid_t", "rgid"),
        ("gid_t", "egid"),
    )),
    "setgid": ("long", (
        ("gid_t", "gid"),
    )),
    "setreuid": ("long", (
        ("uid_t", "ruid"),
        ("uid_t", "euid"),
    )),
    "setuid": ("long", (
        ("uid_t", "uid"),
    )),
    "setresuid": ("long", (
        ("uid_t", "ruid"),
        ("uid_t", "euid"),
        ("uid_t", "suid"),
    )),
    "setresgid": ("long", (
        ("gid_t", "rgid"),
        ("gid_t", "egid"),
        ("gid_t", "sgid"),
    )),
    "setfsuid": ("long", (
        ("uid_t", "uid"),
    )),
    "setfsgid": ("long", (
        ("gid_t", "gid"),
    )),
    "setpgid": ("long", (
        ("pid_t", "pid"),
        ("pid_t", "pgid"),
    )),
    "setsid": ("long", (
    )),
    "setgroups": ("long", (
        ("int", "gidsetsize"),
        ("gid_t *", "grouplist"),
    )),
    "acct": ("long", (
        ("const char *", "name"),
    )),
    "capget": ("long", (
        ("cap_user_header_t", "header"),
        ("cap_user_data_t", "dataptr"),
    )),
    "capset": ("long", (
        ("cap_user_header_t", "header"),
        ("const cap_user_data_t", "data"),
    )),
    "personality": ("long", (
        ("unsigned int", "personality"),
    )),
    "sigpending": ("long", (
        ("old_sigset_t *", "set"),
    )),
    "sigprocmask": ("long", (
        ("int", "how"),
        ("old_sigset_t *", "set"),
        ("old_sigset_t *", "oset"),
    )),
    "sigaltstack": ("long", (
        ("const struct sigaltstack *", "uss"),
        ("struct sigaltstack *", "uoss"),
    )),
    "getitimer": ("long", (
        ("int", "which"),
        ("struct itimerval *", "value"),
    )),
    "setitimer": ("long", (
        ("int", "which"),
        ("struct itimerval *", "value"),
        ("struct itimerval *", "ovalue"),
    )),
    "timer_create": ("long", (
        ("clockid_t", "which_clock"),
        ("struct sigevent *", "timer_event_spec"),
        ("timer_t *", "created_timer_id"),
    )),
    "timer_gettime": ("long", (
        ("timer_t", "timer_id"),
        ("struct itimerspec *", "setting"),
    )),
    "timer_getoverrun": ("long", (
        ("timer_t", "timer_id"),
    )),
    "timer_settime": ("long", (
        ("timer_t", "timer_id"),
        ("int", "flags"),
        ("const struct itimerspec *", "new_setting"),
        ("struct itimerspec *", "old_setting"),
    )),
    "timer_delete": ("long", (
        ("timer_t", "timer_id"),
    )),
    "clock_settime": ("long", (
        ("clockid_t", "which_clock"),
        ("const struct timespec *", "tp"),
    )),
    "clock_gettime": ("long", (
        ("clockid_t", "which_clock"),
        ("struct timespec *", "tp"),
    )),
    "clock_adjtime": ("long", (
        ("clockid_t", "which_clock"),
        ("struct timex *", "tx"),
    )),
    "clock_getres": ("long", (
        ("clockid_t", "which_clock"),
        ("struct timespec *", "tp"),
    )),
    "clock_nanosleep": ("long", (
        ("clockid_t", "which_clock"),
        ("int", "flags"),
        ("const struct timespec *", "rqtp"),
        ("struct timespec *", "rmtp"),
    )),
    "nice": ("long", (
        ("int", "increment"),
    )),
    "sched_setscheduler": ("long", (
        ("pid_t", "pid"),
        ("int", "policy"),
        ("struct sched_param *", "param"),
    )),
    "sched_setparam": ("long", (
        ("pid_t", "pid"),
        ("struct sched_param *", "param"),
    )),
    "sched_setattr": ("long", (
        ("pid_t", "pid"),
        ("struct sched_attr *", "attr"),
        ("unsigned int", "flags"),
    )),
    "sched_getscheduler": ("long", (
        ("pid_t", "pid"),
    )),
    "sched_getparam": ("long", (
        ("pid_t", "pid"),
        ("struct sched_param *", "param"),
    )),
    "sched_getattr": ("long", (
        ("pid_t", "pid"),
        ("struct sched_attr *", "attr"),
        ("unsigned int", "size"),
        ("unsigned int", "flags"),
    )),
    "sched_setaffinity": ("long", (
        ("pid_t", "pid"),
        ("unsigned int", "len"),
        ("unsigned long *", "user_mask_ptr"),
    )),
    "sched_getaffinity": ("long", (
        ("pid_t", "pid"),
        ("unsigned int", "len"),
        ("unsigned long *", "user_mask_ptr"),
    )),
    "sched_yield": ("long", (
    )),
    "sched_get_priority_max": ("long", (
        ("int", "policy"),
    )),
    "sched_get_priority_min": ("long", (
        ("int", "policy"),
    )),
    "sched_rr_get_interval": ("long", (
        ("pid_t", "pid"),
        ("struct timespec *", "interval"),
    )),
    "setpriority": ("long", (
        ("int", "which"),
        ("int", "who"),
        ("int", "niceval"),
    )),
    "getpriority": ("long", (
        ("int", "which"),
        ("int", "who"),
    )),
    "shutdown": ("long", (
        ("int", ""),
        ("int", ""),
    )),
    "reboot": ("long", (
        ("int", "magic1"),
        ("int", "magic2"),
        ("unsigned int", "cmd"),
        ("void *", "arg"),
    )),
    "restart_syscall": ("long", (
    )),
    "kexec_load": ("long", (
        ("unsigned long", "entry"),
        ("unsigned long", "nr_segments"),
        ("struct kexec_segment *", "segments"),
        ("unsigned long", "flags"),
    )),
    "kexec_file_load": ("long", (
        ("int", "kernel_fd"),
        ("int", "initrd_fd"),
        ("unsigned long", "cmdline_len"),
        ("const char *", "cmdline_ptr"),
        ("unsigned long", "flags"),
    )),
    "exit": ("long", (
        ("int", "error_code"),
    )),
    "exit_group": ("long", (
        ("int", "error_code"),
    )),
    "wait4": ("long", (
        ("pid_t", "pid"),
        ("int *", "stat_addr"),
        ("int", "options"),
        ("struct rusage *", "ru"),
    )),
    "waitid": ("long", (
        ("int", "which"),
        ("pid_t", "pid"),
        ("struct siginfo *", "infop"),
        ("int", "options"),
        ("struct rusage *", "ru"),
    )),
    "waitpid": ("long", (
        ("pid_t", "pid"),
        ("int *", "stat_addr"),
        ("int", "options"),
    )),
    "set_tid_address": ("long", (
        ("int *", "tidptr"),
    )),
    "futex": ("long", (
        ("u32 *", "uaddr"),
        ("int", "op"),
        ("u32", "val"),
        ("struct timespec *", "utime"),
        ("u32 *", "uaddr2"),
        ("u32", "val3"),
    )),
    "init_module": ("long", (
        ("void *", "umod"),
        ("unsigned long", "len"),
        ("const char *", "uargs"),
    )),
    "delete_module": ("long", (
        ("const char *", "name_user"),
        ("unsigned int", "flags"),
    )),
    "sigsuspend": ("long", (
        ("old_sigset_t", "mask"),
    )),
    "sigsuspend": ("long", (
        ("int", "unused1"),
        ("int", "unused2"),
        ("old_sigset_t", "mask"),
    )),
    "rt_sigsuspend": ("long", (
        ("sigset_t *", "unewset"),
        ("size_t", "sigsetsize"),
    )),
    "sigaction": ("long", (
        ("int", ""),
        ("const struct old_sigaction *", ""),
        ("struct old_sigaction *", ""),
    )),
    "rt_sigaction": ("long", (
        ("int", ""),
        ("const struct sigaction *", ""),
        ("struct sigaction *", ""),
        ("size_t", ""),
    )),
    "rt_sigprocmask": ("long", (
        ("int", "how"),
        ("sigset_t *", "set"),
        ("sigset_t *", "oset"),
        ("size_t", "sigsetsize"),
    )),
    "rt_sigpending": ("long", (
        ("sigset_t *", "set"),
        ("size_t", "sigsetsize"),
    )),
    "rt_sigtimedwait": ("long", (
        ("const sigset_t *", "uthese"),
        ("siginfo_t *", "uinfo"),
        ("const struct timespec *", "uts"),
        ("size_t", "sigsetsize"),
    )),
    "rt_tgsigqueueinfo": ("long", (
        ("pid_t", "tgid"),
        ("pid_t", "pid"),
        ("int", "sig"),
        ("siginfo_t *", "uinfo"),
    )),
    "kill": ("long", (
        ("int", "pid"),
        ("int", "sig"),
    )),
    "tgkill": ("long", (
        ("int", "tgid"),
        ("int", "pid"),
        ("int", "sig"),
    )),
    "tkill": ("long", (
        ("int", "pid"),
        ("int", "sig"),
    )),
    "rt_sigqueueinfo": ("long", (
        ("int", "pid"),
        ("int", "sig"),
        ("siginfo_t *", "uinfo"),
    )),
    "sgetmask": ("long", (
    )),
    "ssetmask": ("long", (
        ("int", "newmask"),
    )),
    "signal": ("long", (
        ("int", "sig"),
        ("__sighandler_t", "handler"),
    )),
    "pause": ("long", (
    )),
    "sync": ("long", (
    )),
    "fsync": ("long", (
        ("unsigned int", "fd"),
    )),
    "fdatasync": ("long", (
        ("unsigned int", "fd"),
    )),
    "bdflush": ("long", (
        ("int", "func"),
        ("long", "data"),
    )),
    "mount": ("long", (
        ("char *", "dev_name"),
        ("char *", "dir_name"),
        ("char *", "type"),
        ("unsigned long", "flags"),
        ("void *", "data"),
    )),
    "umount": ("long", (
        ("char *", "name"),
        ("int", "flags"),
    )),
    "oldumount": ("long", (
        ("char *", "name"),
    )),
    "truncate": ("long", (
        ("const char *", "path"),
        ("long", "length"),
    )),
    "ftruncate": ("long", (
        ("unsigned int", "fd"),
        ("unsigned long", "length"),
    )),
    "stat": ("long", (
        ("const char *", "filename"),
        ("struct __old_kernel_stat *", "statbuf"),
    )),
    "statfs": ("long", (
        ("const char *", "path"),
        ("struct statfs *", "buf"),
    )),
    "statfs64": ("long", (
        ("const char *", "path"),
        ("size_t", "sz"),
        ("struct statfs64 *", "buf"),
    )),
    "fstatfs": ("long", (
        ("unsigned int", "fd"),
        ("struct statfs *", "buf"),
    )),
    "fstatfs64": ("long", (
        ("unsigned int", "fd"),
        ("size_t", "sz"),
        ("struct statfs64 *", "buf"),
    )),
    "lstat": ("long", (
        ("const char *", "filename"),
        ("struct __old_kernel_stat *", "statbuf"),
    )),
    "fstat": ("long", (
        ("unsigned int", "fd"),
        ("struct __old_kernel_stat *", "statbuf"),
    )),
    "newstat": ("long", (
        ("const char *", "filename"),
        ("struct stat *", "statbuf"),
    )),
    "newlstat": ("long", (
        ("const char *", "filename"),
        ("struct stat *", "statbuf"),
    )),
    "newfstat": ("long", (
        ("unsigned int", "fd"),
        ("struct stat *", "statbuf"),
    )),
    "ustat": ("long", (
        ("unsigned", "dev"),
        ("struct ustat *", "ubuf"),
    )),
    "stat64": ("long", (
        ("const char *", "filename"),
        ("struct stat64 *", "statbuf"),
    )),
    "fstat64": ("long", (
        ("unsigned long", "fd"),
        ("struct stat64 *", "statbuf"),
    )),
    "lstat64": ("long", (
        ("const char *", "filename"),
        ("struct stat64 *", "statbuf"),
    )),
    "fstatat64": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("struct stat64 *", "statbuf"),
        ("int", "flag"),
    )),
    "truncate64": ("long", (
        ("const char *", "path"),
        ("loff_t", "length"),
    )),
    "ftruncate64": ("long", (
        ("unsigned int", "fd"),
        ("loff_t", "length"),
    )),
    "setxattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
        ("const void *", "value"),
        ("size_t", "size"),
        ("int", "flags"),
    )),
    "lsetxattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
        ("const void *", "value"),
        ("size_t", "size"),
        ("int", "flags"),
    )),
    "fsetxattr": ("long", (
        ("int", "fd"),
        ("const char *", "name"),
        ("const void *", "value"),
        ("size_t", "size"),
        ("int", "flags"),
    )),
    "getxattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
        ("void *", "value"),
        ("size_t", "size"),
    )),
    "lgetxattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
        ("void *", "value"),
        ("size_t", "size"),
    )),
    "fgetxattr": ("long", (
        ("int", "fd"),
        ("const char *", "name"),
        ("void *", "value"),
        ("size_t", "size"),
    )),
    "listxattr": ("long", (
        ("const char *", "path"),
        ("char *", "list"),
        ("size_t", "size"),
    )),
    "llistxattr": ("long", (
        ("const char *", "path"),
        ("char *", "list"),
        ("size_t", "size"),
    )),
    "flistxattr": ("long", (
        ("int", "fd"),
        ("char *", "list"),
        ("size_t", "size"),
    )),
    "removexattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
    )),
    "lremovexattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
    )),
    "fremovexattr": ("long", (
        ("int", "fd"),
        ("const char *", "name"),
    )),
    "brk": ("long", (
        ("unsigned long", "brk"),
    )),
    "mprotect": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
        ("unsigned long", "prot"),
    )),
    "mremap": ("long", (
        ("unsigned long", "addr"),
        ("unsigned long", "old_len"),
        ("unsigned long", "new_len"),
        ("unsigned long", "flags"),
        ("unsigned long", "new_addr"),
    )),
    "remap_file_pages": ("long", (
        ("unsigned long", "start"),
        ("unsigned long", "size"),
        ("unsigned long", "prot"),
        ("unsigned long", "pgoff"),
        ("unsigned long", "flags"),
    )),
    "msync": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
        ("int", "flags"),
    )),
    "fadvise64": ("long", (
        ("int", "fd"),
        ("loff_t", "offset"),
        ("size_t", "len"),
        ("int", "advice"),
    )),
    "fadvise64_64": ("long", (
        ("int", "fd"),
        ("loff_t", "offset"),
        ("loff_t", "len"),
        ("int", "advice"),
    )),
    "munmap": ("long", (
        ("unsigned long", "addr"),
        ("size_t", "len"),
    )),
    "mlock": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
    )),
    "munlock": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
    )),
    "mlockall": ("long", (
        ("int", "flags"),
    )),
    "munlockall": ("long", (
    )),
    "madvise": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
        ("int", "behavior"),
    )),
    "mincore": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
        ("unsigned char *", "vec"),
    )),
    "pivot_root": ("long", (
        ("const char *", "new_root"),
        ("const char *", "put_old"),
    )),
    "chroot": ("long", (
        ("const char *", "filename"),
    )),
    "mknod": ("long", (
        ("const char *", "filename"),
        ("umode_t", "mode"),
        ("unsigned", "dev"),
    )),
    "link": ("long", (
        ("const char *", "oldname"),
        ("const char *", "newname"),
    )),
    "symlink": ("long", (
        ("const char *", "old"),
        ("const char *", "new"),
    )),
    "unlink": ("long", (
        ("const char *", "pathname"),
    )),
    "rename": ("long", (
        ("const char *", "oldname"),
        ("const char *", "newname"),
    )),
    "chmod": ("long", (
        ("const char *", "filename"),
        ("umode_t", "mode"),
    )),
    "fchmod": ("long", (
        ("unsigned int", "fd"),
        ("umode_t", "mode"),
    )),
    "fcntl": ("long", (
        ("unsigned int", "fd"),
        ("unsigned int", "cmd"),
        ("unsigned long", "arg"),
    )),
    "fcntl64": ("long", (
        ("unsigned int", "fd"),
        ("unsigned int", "cmd"),
        ("unsigned long", "arg"),
    )),
    "pipe": ("long", (
        ("int *", "fildes"),
    )),
    "pipe2": ("long", (
        ("int *", "fildes"),
        ("int", "flags"),
    )),
    "dup": ("long", (
        ("unsigned int", "fildes"),
    )),
    "dup2": ("long", (
        ("unsigned int", "oldfd"),
        ("unsigned int", "newfd"),
    )),
    "dup3": ("long", (
        ("unsigned int", "oldfd"),
        ("unsigned int", "newfd"),
        ("int", "flags"),
    )),
    "ioperm": ("long", (
        ("unsigned long", "from"),
        ("unsigned long", "num"),
        ("int", "on"),
    )),
    "ioctl": ("long", (
        ("unsigned int", "fd"),
        ("unsigned int", "cmd"),
        ("unsigned long", "arg"),
    )),
    "flock": ("long", (
        ("unsigned int", "fd"),
        ("unsigned int", "cmd"),
    )),
    "io_setup": ("long", (
        ("unsigned", "nr_reqs"),
        ("aio_context_t *", "ctx"),
    )),
    "io_destroy": ("long", (
        ("aio_context_t", "ctx"),
    )),
    "io_getevents": ("long", (
        ("aio_context_t", "ctx_id"),
        ("long", "min_nr"),
        ("long", "nr"),
        ("struct io_event *", "events"),
        ("struct timespec *", "timeout"),
    )),
    "io_submit": ("long", (
        ("", "aio_context_t"),
        ("long", ""),
        ("struct iocb * *", ""),
    )),
    "io_cancel": ("long", (
        ("aio_context_t", "ctx_id"),
        ("struct iocb *", "iocb"),
        ("struct io_event *", "result"),
    )),
    "sendfile": ("long", (
        ("int", "out_fd"),
        ("int", "in_fd"),
        ("off_t *", "offset"),
        ("size_t", "count"),
    )),
    "sendfile64": ("long", (
        ("int", "out_fd"),
        ("int", "in_fd"),
        ("loff_t *", "offset"),
        ("size_t", "count"),
    )),
    "readlink": ("long", (
        ("const char *", "path"),
        ("char *", "buf"),
        ("int", "bufsiz"),
    )),
    "creat": ("long", (
        ("const char *", "pathname"),
        ("umode_t", "mode"),
    )),
    "open": ("long", (
        ("const char *", "filename"),
        ("int", "flags"),
        ("umode_t", "mode"),
    )),
    "close": ("long", (
        ("unsigned int", "fd"),
    )),
    "access": ("long", (
        ("const char *", "filename"),
        ("int", "mode"),
    )),
    "vhangup": ("long", (
    )),
    "chown": ("long", (
        ("const char *", "filename"),
        ("uid_t", "user"),
        ("gid_t", "group"),
    )),
    "lchown": ("long", (
        ("const char *", "filename"),
        ("uid_t", "user"),
        ("gid_t", "group"),
    )),
    "fchown": ("long", (
        ("unsigned int", "fd"),
        ("uid_t", "user"),
        ("gid_t", "group"),
    )),
    "chown16": ("long", (
        ("const char *", "filename"),
        ("old_uid_t", "user"),
        ("old_gid_t", "group"),
    )),
    "lchown16": ("long", (
        ("const char *", "filename"),
        ("old_uid_t", "user"),
        ("old_gid_t", "group"),
    )),
    "fchown16": ("long", (
        ("unsigned int", "fd"),
        ("old_uid_t", "user"),
        ("old_gid_t", "group"),
    )),
    "setregid16": ("long", (
        ("old_gid_t", "rgid"),
        ("old_gid_t", "egid"),
    )),
    "setgid16": ("long", (
        ("old_gid_t", "gid"),
    )),
    "setreuid16": ("long", (
        ("old_uid_t", "ruid"),
        ("old_uid_t", "euid"),
    )),
    "setuid16": ("long", (
        ("old_uid_t", "uid"),
    )),
    "setresuid16": ("long", (
        ("old_uid_t", "ruid"),
        ("old_uid_t", "euid"),
        ("old_uid_t", "suid"),
    )),
    "getresuid16": ("long", (
        ("old_uid_t *", "ruid"),
        ("old_uid_t *", "euid"),
        ("old_uid_t *", "suid"),
    )),
    "setresgid16": ("long", (
        ("old_gid_t", "rgid"),
        ("old_gid_t", "egid"),
        ("old_gid_t", "sgid"),
    )),
    "getresgid16": ("long", (
        ("old_gid_t *", "rgid"),
        ("old_gid_t *", "egid"),
        ("old_gid_t *", "sgid"),
    )),
    "setfsuid16": ("long", (
        ("old_uid_t", "uid"),
    )),
    "setfsgid16": ("long", (
        ("old_gid_t", "gid"),
    )),
    "getgroups16": ("long", (
        ("int", "gidsetsize"),
        ("old_gid_t *", "grouplist"),
    )),
    "setgroups16": ("long", (
        ("int", "gidsetsize"),
        ("old_gid_t *", "grouplist"),
    )),
    "getuid16": ("long", (
    )),
    "geteuid16": ("long", (
    )),
    "getgid16": ("long", (
    )),
    "getegid16": ("long", (
    )),
    "utime": ("long", (
        ("char *", "filename"),
        ("struct utimbuf *", "times"),
    )),
    "utimes": ("long", (
        ("char *", "filename"),
        ("struct timeval *", "utimes"),
    )),
    "lseek": ("long", (
        ("unsigned int", "fd"),
        ("off_t", "offset"),
        ("unsigned int", "whence"),
    )),
    "llseek": ("long", (
        ("unsigned int", "fd"),
        ("unsigned long", "offset_high"),
        ("unsigned long", "offset_low"),
        ("loff_t *", "result"),
        ("unsigned int", "whence"),
    )),
    "read": ("long", (
        ("unsigned int", "fd"),
        ("char *", "buf"),
        ("size_t", "count"),
    )),
    "readahead": ("long", (
        ("int", "fd"),
        ("loff_t", "offset"),
        ("size_t", "count"),
    )),
    "readv": ("long", (
        ("unsigned long", "fd"),
        ("const struct iovec *", "vec"),
        ("unsigned long", "vlen"),
    )),
    "write": ("long", (
        ("unsigned int", "fd"),
        ("const char *", "buf"),
        ("size_t", "count"),
    )),
    "writev": ("long", (
        ("unsigned long", "fd"),
        ("const struct iovec *", "vec"),
        ("unsigned long", "vlen"),
    )),
    "pread64": ("long", (
        ("unsigned int", "fd"),
        ("char *", "buf"),
        ("size_t", "count"),
        ("loff_t", "pos"),
    )),
    "pwrite64": ("long", (
        ("unsigned int", "fd"),
        ("const char *", "buf"),
        ("size_t", "count"),
        ("loff_t", "pos"),
    )),
    "preadv": ("long", (
        ("unsigned long", "fd"),
        ("const struct iovec *", "vec"),
        ("unsigned long", "vlen"),
        ("unsigned long", "pos_l"),
        ("unsigned long", "pos_h"),
    )),
    "pwritev": ("long", (
        ("unsigned long", "fd"),
        ("const struct iovec *", "vec"),
        ("unsigned long", "vlen"),
        ("unsigned long", "pos_l"),
        ("unsigned long", "pos_h"),
    )),
    "getcwd": ("long", (
        ("char *", "buf"),
        ("unsigned long", "size"),
    )),
    "mkdir": ("long", (
        ("const char *", "pathname"),
        ("umode_t", "mode"),
    )),
    "chdir": ("long", (
        ("const char *", "filename"),
    )),
    "fchdir": ("long", (
        ("unsigned int", "fd"),
    )),
    "rmdir": ("long", (
        ("const char *", "pathname"),
    )),
    "lookup_dcookie": ("long", (
        ("u64", "cookie64"),
        ("char *", "buf"),
        ("size_t", "len"),
    )),
    "quotactl": ("long", (
        ("unsigned int", "cmd"),
        ("const char *", "special"),
        ("qid_t", "id"),
        ("void *", "addr"),
    )),
    "getdents": ("long", (
        ("unsigned int", "fd"),
        ("struct linux_dirent *", "dirent"),
        ("unsigned int", "count"),
    )),
    "getdents64": ("long", (
        ("unsigned int", "fd"),
        ("struct linux_dirent64 *", "dirent"),
        ("unsigned int", "count"),
    )),
    "setsockopt": ("long", (
        ("int", "fd"),
        ("int", "level"),
        ("int", "optname"),
        ("char *", "optval"),
        ("int", "optlen"),
    )),
    "getsockopt": ("long", (
        ("int", "fd"),
        ("int", "level"),
        ("int", "optname"),
        ("char *", "optval"),
        ("int *", "optlen"),
    )),
    "bind": ("long", (
        ("int", ""),
        ("struct sockaddr *", ""),
        ("int", ""),
    )),
    "connect": ("long", (
        ("int", ""),
        ("struct sockaddr *", ""),
        ("int", ""),
    )),
    "accept": ("long", (
        ("int", ""),
        ("struct sockaddr *", ""),
        ("int *", ""),
    )),
    "accept4": ("long", (
        ("int", ""),
        ("struct sockaddr *", ""),
        ("int *", ""),
        ("int", ""),
    )),
    "getsockname": ("long", (
        ("int", ""),
        ("struct sockaddr *", ""),
        ("int *", ""),
    )),
    "getpeername": ("long", (
        ("int", ""),
        ("struct sockaddr *", ""),
        ("int *", ""),
    )),
    "send": ("long", (
        ("int", ""),
        ("void *", ""),
        ("size_t", ""),
        ("", "unsigned"),
    )),
    "sendto": ("long", (
        ("int", ""),
        ("void *", ""),
        ("size_t", ""),
        ("", "unsigned"),
        ("struct sockaddr *", ""),
        ("int", ""),
    )),
    "sendmsg": ("long", (
        ("int", "fd"),
        ("struct user_msghdr *", "msg"),
        ("unsigned", "flags"),
    )),
    "sendmmsg": ("long", (
        ("int", "fd"),
        ("struct mmsghdr *", "msg"),
        ("unsigned int", "vlen"),
        ("unsigned", "flags"),
    )),
    "recv": ("long", (
        ("int", ""),
        ("void *", ""),
        ("size_t", ""),
        ("", "unsigned"),
    )),
    "recvfrom": ("long", (
        ("int", ""),
        ("void *", ""),
        ("size_t", ""),
        ("", "unsigned"),
        ("struct sockaddr *", ""),
        ("int *", ""),
    )),
    "recvmsg": ("long", (
        ("int", "fd"),
        ("struct user_msghdr *", "msg"),
        ("unsigned", "flags"),
    )),
    "recvmmsg": ("long", (
        ("int", "fd"),
        ("struct mmsghdr *", "msg"),
        ("unsigned int", "vlen"),
        ("unsigned", "flags"),
        ("struct timespec *", "timeout"),
    )),
    "socket": ("long", (
        ("int", ""),
        ("int", ""),
        ("int", ""),
    )),
    "socketpair": ("long", (
        ("int", ""),
        ("int", ""),
        ("int", ""),
        ("int *", ""),
    )),
    "socketcall": ("long", (
        ("int", "call"),
        ("unsigned long *", "args"),
    )),
    "listen": ("long", (
        ("int", ""),
        ("int", ""),
    )),
    "poll": ("long", (
        ("struct pollfd *", "ufds"),
        ("unsigned int", "nfds"),
        ("int", "timeout"),
    )),
    "select": ("long", (
        ("int", "n"),
        ("fd_set *", "inp"),
        ("fd_set *", "outp"),
        ("fd_set *", "exp"),
        ("struct timeval *", "tvp"),
    )),
    "old_select": ("long", (
        ("struct sel_arg_struct *", "arg"),
    )),
    "epoll_create": ("long", (
        ("int", "size"),
    )),
    "epoll_create1": ("long", (
        ("int", "flags"),
    )),
    "epoll_ctl": ("long", (
        ("int", "epfd"),
        ("int", "op"),
        ("int", "fd"),
        ("struct epoll_event *", "event"),
    )),
    "epoll_wait": ("long", (
        ("int", "epfd"),
        ("struct epoll_event *", "events"),
        ("int", "maxevents"),
        ("int", "timeout"),
    )),
    "epoll_pwait": ("long", (
        ("int", "epfd"),
        ("struct epoll_event *", "events"),
        ("int", "maxevents"),
        ("int", "timeout"),
        ("const sigset_t *", "sigmask"),
        ("size_t", "sigsetsize"),
    )),
    "gethostname": ("long", (
        ("char *", "name"),
        ("int", "len"),
    )),
    "sethostname": ("long", (
        ("char *", "name"),
        ("int", "len"),
    )),
    "setdomainname": ("long", (
        ("char *", "name"),
        ("int", "len"),
    )),
    "newuname": ("long", (
        ("struct new_utsname *", "name"),
    )),
    "uname": ("long", (
        ("struct old_utsname *", ""),
    )),
    "olduname": ("long", (
        ("struct oldold_utsname *", ""),
    )),
    "getrlimit": ("long", (
        ("unsigned int", "resource"),
        ("struct rlimit *", "rlim"),
    )),
    "old_getrlimit": ("long", (
        ("unsigned int", "resource"),
        ("struct rlimit *", "rlim"),
    )),
    "setrlimit": ("long", (
        ("unsigned int", "resource"),
        ("struct rlimit *", "rlim"),
    )),
    "prlimit64": ("long", (
        ("pid_t", "pid"),
        ("unsigned int", "resource"),
        ("const struct rlimit64 *", "new_rlim"),
        ("struct rlimit64 *", "old_rlim"),
    )),
    "getrusage": ("long", (
        ("int", "who"),
        ("struct rusage *", "ru"),
    )),
    "umask": ("long", (
        ("int", "mask"),
    )),
    "msgget": ("long", (
        ("key_t", "key"),
        ("int", "msgflg"),
    )),
    "msgsnd": ("long", (
        ("int", "msqid"),
        ("struct msgbuf *", "msgp"),
        ("size_t", "msgsz"),
        ("int", "msgflg"),
    )),
    "msgrcv": ("long", (
        ("int", "msqid"),
        ("struct msgbuf *", "msgp"),
        ("size_t", "msgsz"),
        ("long", "msgtyp"),
        ("int", "msgflg"),
    )),
    "msgctl": ("long", (
        ("int", "msqid"),
        ("int", "cmd"),
        ("struct msqid_ds *", "buf"),
    )),
    "semget": ("long", (
        ("key_t", "key"),
        ("int", "nsems"),
        ("int", "semflg"),
    )),
    "semop": ("long", (
        ("int", "semid"),
        ("struct sembuf *", "sops"),
        ("unsigned", "nsops"),
    )),
    "semctl": ("long", (
        ("int", "semid"),
        ("int", "semnum"),
        ("int", "cmd"),
        ("unsigned long", "arg"),
    )),
    "semtimedop": ("long", (
        ("int", "semid"),
        ("struct sembuf *", "sops"),
        ("unsigned", "nsops"),
        ("const struct timespec *", "timeout"),
    )),
    "shmat": ("long", (
        ("int", "shmid"),
        ("char *", "shmaddr"),
        ("int", "shmflg"),
    )),
    "shmget": ("long", (
        ("key_t", "key"),
        ("size_t", "size"),
        ("int", "flag"),
    )),
    "shmdt": ("long", (
        ("char *", "shmaddr"),
    )),
    "shmctl": ("long", (
        ("int", "shmid"),
        ("int", "cmd"),
        ("struct shmid_ds *", "buf"),
    )),
    "ipc": ("long", (
        ("unsigned int", "call"),
        ("int", "first"),
        ("unsigned long", "second"),
        ("unsigned long", "third"),
        ("void *", "ptr"),
        ("long", "fifth"),
    )),
    "mq_open": ("long", (
        ("const char *", "name"),
        ("int", "oflag"),
        ("umode_t", "mode"),
        ("struct mq_attr *", "attr"),
    )),
    "mq_unlink": ("long", (
        ("const char *", "name"),
    )),
    "mq_timedsend": ("long", (
        ("mqd_t", "mqdes"),
        ("const char *", "msg_ptr"),
        ("size_t", "msg_len"),
        ("unsigned int", "msg_prio"),
        ("const struct timespec *", "abs_timeout"),
    )),
    "mq_timedreceive": ("long", (
        ("mqd_t", "mqdes"),
        ("char *", "msg_ptr"),
        ("size_t", "msg_len"),
        ("unsigned int *", "msg_prio"),
        ("const struct timespec *", "abs_timeout"),
    )),
    "mq_notify": ("long", (
        ("mqd_t", "mqdes"),
        ("const struct sigevent *", "notification"),
    )),
    "mq_getsetattr": ("long", (
        ("mqd_t", "mqdes"),
        ("const struct mq_attr *", "mqstat"),
        ("struct mq_attr *", "omqstat"),
    )),
    "pciconfig_iobase": ("long", (
        ("long", "which"),
        ("unsigned long", "bus"),
        ("unsigned long", "devfn"),
    )),
    "pciconfig_read": ("long", (
        ("unsigned long", "bus"),
        ("unsigned long", "dfn"),
        ("unsigned long", "off"),
        ("unsigned long", "len"),
        ("void *", "buf"),
    )),
    "pciconfig_write": ("long", (
        ("unsigned long", "bus"),
        ("unsigned long", "dfn"),
        ("unsigned long", "off"),
        ("unsigned long", "len"),
        ("void *", "buf"),
    )),
    "prctl": ("long", (
        ("int", "option"),
        ("unsigned long", "arg2"),
        ("unsigned long", "arg3"),
        ("unsigned long", "arg4"),
        ("unsigned long", "arg5"),
    )),
    "swapon": ("long", (
        ("const char *", "specialfile"),
        ("int", "swap_flags"),
    )),
    "swapoff": ("long", (
        ("const char *", "specialfile"),
    )),
    "sysctl": ("long", (
        ("struct __sysctl_args *", "args"),
    )),
    "sysinfo": ("long", (
        ("struct sysinfo *", "info"),
    )),
    "sysfs": ("long", (
        ("int", "option"),
        ("unsigned long", "arg1"),
        ("unsigned long", "arg2"),
    )),
    "syslog": ("long", (
        ("int", "type"),
        ("char *", "buf"),
        ("int", "len"),
    )),
    "uselib": ("long", (
        ("const char *", "library"),
    )),
    "ni_syscall": ("long", (
    )),
    "ptrace": ("long", (
        ("long", "request"),
        ("long", "pid"),
        ("unsigned long", "addr"),
        ("unsigned long", "data"),
    )),
    "add_key": ("long", (
        ("const char *", "_type"),
        ("const char *", "_description"),
        ("const void *", "_payload"),
        ("size_t", "plen"),
        ("key_serial_t", "destringid"),
    )),
    "request_key": ("long", (
        ("const char *", "_type"),
        ("const char *", "_description"),
        ("const char *", "_callout_info"),
        ("key_serial_t", "destringid"),
    )),
    "keyctl": ("long", (
        ("int", "cmd"),
        ("unsigned long", "arg2"),
        ("unsigned long", "arg3"),
        ("unsigned long", "arg4"),
        ("unsigned long", "arg5"),
    )),
    "ioprio_set": ("long", (
        ("int", "which"),
        ("int", "who"),
        ("int", "ioprio"),
    )),
    "ioprio_get": ("long", (
        ("int", "which"),
        ("int", "who"),
    )),
    "set_mempolicy": ("long", (
        ("int", "mode"),
        ("const unsigned long *", "nmask"),
        ("unsigned long", "maxnode"),
    )),
    "migrate_pages": ("long", (
        ("pid_t", "pid"),
        ("unsigned long", "maxnode"),
        ("const unsigned long *", "from"),
        ("const unsigned long *", "to"),
    )),
    "move_pages": ("long", (
        ("pid_t", "pid"),
        ("unsigned long", "nr_pages"),
        ("const void * *", "pages"),
        ("const int *", "nodes"),
        ("int *", "status"),
        ("int", "flags"),
    )),
    "mbind": ("long", (
        ("unsigned long", "start"),
        ("unsigned long", "len"),
        ("unsigned long", "mode"),
        ("const unsigned long *", "nmask"),
        ("unsigned long", "maxnode"),
        ("unsigned", "flags"),
    )),
    "get_mempolicy": ("long", (
        ("int *", "policy"),
        ("unsigned long *", "nmask"),
        ("unsigned long", "maxnode"),
        ("unsigned long", "addr"),
        ("unsigned long", "flags"),
    )),
    "inotify_init": ("long", (
    )),
    "inotify_init1": ("long", (
        ("int", "flags"),
    )),
    "inotify_add_watch": ("long", (
        ("int", "fd"),
        ("const char *", "path"),
        ("u32", "mask"),
    )),
    "inotify_rm_watch": ("long", (
        ("int", "fd"),
        ("__s32", "wd"),
    )),
    "spu_run": ("long", (
        ("int", "fd"),
        ("__u32 *", "unpc"),
        ("__u32 *", "ustatus"),
    )),
    "spu_create": ("long", (
        ("const char *", "name"),
        ("unsigned int", "flags"),
        ("umode_t", "mode"),
        ("int", "fd"),
    )),
    "mknodat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("umode_t", "mode"),
        ("unsigned", "dev"),
    )),
    "mkdirat": ("long", (
        ("int", "dfd"),
        ("const char *", "pathname"),
        ("umode_t", "mode"),
    )),
    "unlinkat": ("long", (
        ("int", "dfd"),
        ("const char *", "pathname"),
        ("int", "flag"),
    )),
    "symlinkat": ("long", (
        ("const char *", "oldname"),
        ("int", "newdfd"),
        ("const char *", "newname"),
    )),
    "linkat": ("long", (
        ("int", "olddfd"),
        ("const char *", "oldname"),
        ("int", "newdfd"),
        ("const char *", "newname"),
        ("int", "flags"),
    )),
    "renameat": ("long", (
        ("int", "olddfd"),
        ("const char *", "oldname"),
        ("int", "newdfd"),
        ("const char *", "newname"),
    )),
    "renameat2": ("long", (
        ("int", "olddfd"),
        ("const char *", "oldname"),
        ("int", "newdfd"),
        ("const char *", "newname"),
        ("unsigned int", "flags"),
    )),
    "futimesat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("struct timeval *", "utimes"),
    )),
    "faccessat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("int", "mode"),
    )),
    "fchmodat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("umode_t", "mode"),
    )),
    "fchownat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("uid_t", "user"),
        ("gid_t", "group"),
        ("int", "flag"),
    )),
    "openat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("int", "flags"),
        ("umode_t", "mode"),
    )),
    "newfstatat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("struct stat *", "statbuf"),
        ("int", "flag"),
    )),
    "readlinkat": ("long", (
        ("int", "dfd"),
        ("const char *", "path"),
        ("char *", "buf"),
        ("int", "bufsiz"),
    )),
    "utimensat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("struct timespec *", "utimes"),
        ("int", "flags"),
    )),
    "unshare": ("long", (
        ("unsigned long", "unshare_flags"),
    )),
    "splice": ("long", (
        ("int", "fd_in"),
        ("loff_t *", "off_in"),
        ("int", "fd_out"),
        ("loff_t *", "off_out"),
        ("size_t", "len"),
        ("unsigned int", "flags"),
    )),
    "vmsplice": ("long", (
        ("int", "fd"),
        ("const struct iovec *", "iov"),
        ("unsigned long", "nr_segs"),
        ("unsigned int", "flags"),
    )),
    "tee": ("long", (
        ("int", "fdin"),
        ("int", "fdout"),
        ("size_t", "len"),
        ("unsigned int", "flags"),
    )),
    "sync_file_range": ("long", (
        ("int", "fd"),
        ("loff_t", "offset"),
        ("loff_t", "nbytes"),
        ("unsigned int", "flags"),
    )),
    "sync_file_range2": ("long", (
        ("int", "fd"),
        ("unsigned int", "flags"),
        ("loff_t", "offset"),
        ("loff_t", "nbytes"),
    )),
    "get_robust_list": ("long", (
        ("int", "pid"),
        ("struct robust_list_head * *", "head_ptr"),
        ("size_t *", "len_ptr"),
    )),
    "set_robust_list": ("long", (
        ("struct robust_list_head *", "head"),
        ("size_t", "len"),
    )),
    "getcpu": ("long", (
        ("unsigned *", "cpu"),
        ("unsigned *", "node"),
        ("struct getcpu_cache *", "cache"),
    )),
    "signalfd": ("long", (
        ("int", "ufd"),
        ("sigset_t *", "user_mask"),
        ("size_t", "sizemask"),
    )),
    "signalfd4": ("long", (
        ("int", "ufd"),
        ("sigset_t *", "user_mask"),
        ("size_t", "sizemask"),
        ("int", "flags"),
    )),
    "timerfd_create": ("long", (
        ("int", "clockid"),
        ("int", "flags"),
    )),
    "timerfd_settime": ("long", (
        ("int", "ufd"),
        ("int", "flags"),
        ("const struct itimerspec *", "utmr"),
        ("struct itimerspec *", "otmr"),
    )),
    "timerfd_gettime": ("long", (
        ("int", "ufd"),
        ("struct itimerspec *", "otmr"),
    )),
    "eventfd": ("long", (
        ("unsigned int", "count"),
    )),
    "eventfd2": ("long", (
        ("unsigned int", "count"),
        ("int", "flags"),
    )),
    "memfd_create": ("long", (
        ("const char *", "uname_ptr"),
        ("unsigned int", "flags"),
    )),
    "userfaultfd": ("long", (
        ("int", "flags"),
    )),
    "fallocate": ("long", (
        ("int", "fd"),
        ("int", "mode"),
        ("loff_t", "offset"),
        ("loff_t", "len"),
    )),
    "old_readdir": ("long", (
        ("unsigned int", ""),
        ("struct old_linux_dirent *", ""),
        ("unsigned int", ""),
    )),
    "pselect6": ("long", (
        ("int", ""),
        ("fd_set *", ""),
        ("fd_set *", ""),
        ("fd_set *", ""),
        ("struct timespec *", ""),
        ("void *", ""),
    )),
    "ppoll": ("long", (
        ("struct pollfd *", ""),
        ("unsigned int", ""),
        ("struct timespec *", ""),
        ("const sigset_t *", ""),
        ("size_t", ""),
    )),
    "fanotify_init": ("long", (
        ("unsigned int", "flags"),
        ("unsigned int", "event_f_flags"),
    )),
    "fanotify_mark": ("long", (
        ("int", "fanotify_fd"),
        ("unsigned int", "flags"),
        ("u64", "mask"),
        ("int", "fd"),
        ("const char *", "pathname"),
    )),
    "syncfs": ("long", (
        ("int", "fd"),
    )),
    "fork": ("long", (
    )),
    "vfork": ("long", (
    )),
    "clone": ("long", (
        ("unsigned long", ""),
        ("unsigned long", ""),
        ("int *", ""),
        ("unsigned long", ""),
        ("int *", ""),
    )),
    "clone": ("long", (
        ("unsigned long", ""),
        ("unsigned long", ""),
        ("int", ""),
        ("int *", ""),
        ("int *", ""),
        ("unsigned long", ""),
    )),
    "clone": ("long", (
        ("unsigned long", ""),
        ("unsigned long", ""),
        ("int *", ""),
        ("int *", ""),
        ("unsigned long", ""),
    )),
    "execve": ("long", (
        ("const char *", "filename"),
        ("const char *const *", "argv"),
        ("const char *const *", "envp"),
    )),
    "perf_event_open": ("long", (
        ("struct perf_event_attr *", "attr_uptr"),
        ("pid_t", "pid"),
        ("int", "cpu"),
        ("int", "group_fd"),
        ("unsigned long", "flags"),
    )),
    "mmap_pgoff": ("long", (
        ("unsigned long", "addr"),
        ("unsigned long", "len"),
        ("unsigned long", "prot"),
        ("unsigned long", "flags"),
        ("unsigned long", "fd"),
        ("unsigned long", "pgoff"),
    )),
    "old_mmap": ("long", (
        ("struct mmap_arg_struct *", "arg"),
    )),
    "name_to_handle_at": ("long", (
        ("int", "dfd"),
        ("const char *", "name"),
        ("struct file_handle *", "handle"),
        ("int *", "mnt_id"),
        ("int", "flag"),
    )),
    "open_by_handle_at": ("long", (
        ("int", "mountdirfd"),
        ("struct file_handle *", "handle"),
        ("int", "flags"),
    )),
    "setns": ("long", (
        ("int", "fd"),
        ("int", "nstype"),
    )),
    "process_vm_readv": ("long", (
        ("pid_t", "pid"),
        ("const struct iovec *", "lvec"),
        ("unsigned long", "liovcnt"),
        ("const struct iovec *", "rvec"),
        ("unsigned long", "riovcnt"),
        ("unsigned long", "flags"),
    )),
    "process_vm_writev": ("long", (
        ("pid_t", "pid"),
        ("const struct iovec *", "lvec"),
        ("unsigned long", "liovcnt"),
        ("const struct iovec *", "rvec"),
        ("unsigned long", "riovcnt"),
        ("unsigned long", "flags"),
    )),
    "kcmp": ("long", (
        ("pid_t", "pid1"),
        ("pid_t", "pid2"),
        ("int", "type"),
        ("unsigned long", "idx1"),
        ("unsigned long", "idx2"),
    )),
    "finit_module": ("long", (
        ("int", "fd"),
        ("const char *", "uargs"),
        ("int", "flags"),
    )),
    "seccomp": ("long", (
        ("unsigned int", "op"),
        ("unsigned int", "flags"),
        ("const char *", "uargs"),
    )),
    "getrandom": ("long", (
        ("char *", "buf"),
        ("size_t", "count"),
        ("unsigned int", "flags"),
    )),
    "bpf": ("long", (
        ("int", "cmd"),
        ("union bpf_attr *", "attr"),
        ("unsigned int", "size"),
    )),
    "execveat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("const char *const *", "argv"),
        ("const char *const *", "envp"),
        ("int", "flags"),
    )),
    "membarrier": ("long", (
        ("int", "cmd"),
        ("int", "flags"),
    )),
    "copy_file_range": ("long", (
        ("int", "fd_in"),
        ("loff_t *", "off_in"),
        ("int", "fd_out"),
        ("loff_t *", "off_out"),
        ("size_t", "len"),
        ("unsigned int", "flags"),
    )),
    "mlock2": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
        ("int", "flags"),
    )),
}

for orig, copies in ALIASES.items():
    orig = SYSCALL_PROTOTYPES[orig]
    for copy in copies:
        SYSCALL_PROTOTYPES[copy] = orig

