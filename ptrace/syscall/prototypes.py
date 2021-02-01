# From Linux kernel source code
#    include/linux/syscalls.h
#    arch/i386/kernel/syscall_table.S
#    arch/um/include/sysdep-i386/syscalls.h
#    arch/um/sys-i386/sys_call_table.S

ALIASES = {
    "brk": ("break",),
    "fadvise64": ("posix_fadvise",),
    "fstatat64": ("fstatat",),
    "getcwd": ("__getcwd",),
    "mmap_pgoff": ("mmap", "mmap2",),
    "pread64": ("pread",),
    "prlimit64": ("prlimit",),
    "pselect6": ("pselect",),
    "pwrite64": ("pwrite",),
}

# Name of arguments containing a filename or a path
FILENAME_ARGUMENTS = set(
    ("filename", "pathname", "path", "oldname", "newname", "old", "new"))

SYSCALL_PROTOTYPES = {
    "accept": ("long", (
        ("int", "sockfd"),
        ("struct sockaddr *", "addr"),
        ("int *", "addrlen"),
    )),
    "accept4": ("long", (
        ("int", "sockfd"),
        ("struct sockaddr *", "addr"),
        ("int *", "addrlen"),
        ("int", "flags"),
    )),
    "access": ("long", (
        ("const char *", "filename"),
        ("int", "mode"),
    )),
    "acct": ("long", (
        ("const char *", "name"),
    )),
    "add_key": ("long", (
        ("const char *", "_type"),
        ("const char *", "_description"),
        ("const void *", "_payload"),
        ("size_t", "plen"),
        ("key_serial_t", "destringid"),
    )),
    "adjtimex": ("long", (
        ("struct timex *", "txc_p"),
    )),
    "alarm": ("long", (
        ("unsigned int", "seconds"),
    )),
    "bdflush": ("long", (
        ("int", "func"),
        ("long", "data"),
    )),
    "bind": ("long", (
        ("int", "sockfd"),
        ("struct sockaddr *", "addr"),
        ("int", "addrlen"),
    )),
    "bpf": ("long", (
        ("int", "cmd"),
        ("union bpf_attr *", "attr"),
        ("unsigned int", "size"),
    )),
    "brk": ("long", (
        ("unsigned long", "brk"),
    )),
    "capget": ("long", (
        ("cap_user_header_t", "header"),
        ("cap_user_data_t", "dataptr"),
    )),
    "capset": ("long", (
        ("cap_user_header_t", "header"),
        ("const cap_user_data_t", "data"),
    )),
    "chdir": ("long", (
        ("const char *", "filename"),
    )),
    "chmod": ("long", (
        ("const char *", "filename"),
        ("umode_t", "mode"),
    )),
    "chown": ("long", (
        ("const char *", "filename"),
        ("uid_t", "user"),
        ("gid_t", "group"),
    )),
    "chown16": ("long", (
        ("const char *", "filename"),
        ("old_uid_t", "user"),
        ("old_gid_t", "group"),
    )),
    "chroot": ("long", (
        ("const char *", "filename"),
    )),
    "clock_adjtime": ("long", (
        ("clockid_t", "which_clock"),
        ("struct timex *", "tx"),
    )),
    "clock_getres": ("long", (
        ("clockid_t", "which_clock"),
        ("struct timespec *", "tp"),
    )),
    "clock_gettime": ("long", (
        ("clockid_t", "which_clock"),
        ("struct timespec *", "tp"),
    )),
    "clock_nanosleep": ("long", (
        ("clockid_t", "which_clock"),
        ("int", "flags"),
        ("const struct timespec *", "rqtp"),
        ("struct timespec *", "rmtp"),
    )),
    "clock_settime": ("long", (
        ("clockid_t", "which_clock"),
        ("const struct timespec *", "tp"),
    )),
    "clone": ("long", (
        ("unsigned long", "flags"),
        ("unsigned long", "child_stack"),
        ("int *", "ptid"),
        ("int *", "ctid"),
        ("unsigned long", "regs"),
    )),
    "close": ("long", (
        ("unsigned int", "fd"),
    )),
    "connect": ("long", (
        ("int", "sockfd"),
        ("struct sockaddr *", "addr"),
        ("int", "addrlen"),
    )),
    "copy_file_range": ("long", (
        ("int", "fd_in"),
        ("loff_t *", "off_in"),
        ("int", "fd_out"),
        ("loff_t *", "off_out"),
        ("size_t", "len"),
        ("unsigned int", "flags"),
    )),
    "creat": ("long", (
        ("const char *", "pathname"),
        ("umode_t", "mode"),
    )),
    "delete_module": ("long", (
        ("const char *", "name_user"),
        ("unsigned int", "flags"),
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
    "epoll_pwait": ("long", (
        ("int", "epfd"),
        ("struct epoll_event *", "events"),
        ("int", "maxevents"),
        ("int", "timeout"),
        ("const sigset_t *", "sigmask"),
        ("size_t", "sigsetsize"),
    )),
    "epoll_wait": ("long", (
        ("int", "epfd"),
        ("struct epoll_event *", "events"),
        ("int", "maxevents"),
        ("int", "timeout"),
    )),
    "eventfd": ("long", (
        ("unsigned int", "count"),
    )),
    "eventfd2": ("long", (
        ("unsigned int", "count"),
        ("int", "flags"),
    )),
    "execve": ("long", (
        ("const char *", "filename"),
        ("const char *const *", "argv"),
        ("const char *const *", "envp"),
    )),
    "execveat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("const char *const *", "argv"),
        ("const char *const *", "envp"),
        ("int", "flags"),
    )),
    "exit": ("long", (
        ("int", "error_code"),
    )),
    "exit_group": ("long", (
        ("int", "error_code"),
    )),
    "faccessat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("int", "mode"),
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
    "fallocate": ("long", (
        ("int", "fd"),
        ("int", "mode"),
        ("loff_t", "offset"),
        ("loff_t", "len"),
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
    "fchdir": ("long", (
        ("unsigned int", "fd"),
    )),
    "fchmod": ("long", (
        ("unsigned int", "fd"),
        ("umode_t", "mode"),
    )),
    "fchmodat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("umode_t", "mode"),
    )),
    "fchown": ("long", (
        ("unsigned int", "fd"),
        ("uid_t", "user"),
        ("gid_t", "group"),
    )),
    "fchown16": ("long", (
        ("unsigned int", "fd"),
        ("old_uid_t", "user"),
        ("old_gid_t", "group"),
    )),
    "fchownat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("uid_t", "user"),
        ("gid_t", "group"),
        ("int", "flag"),
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
    "fdatasync": ("long", (
        ("unsigned int", "fd"),
    )),
    "fgetxattr": ("long", (
        ("int", "fd"),
        ("const char *", "name"),
        ("void *", "value"),
        ("size_t", "size"),
    )),
    "finit_module": ("long", (
        ("int", "fd"),
        ("const char *", "uargs"),
        ("int", "flags"),
    )),
    "flistxattr": ("long", (
        ("int", "fd"),
        ("char *", "list"),
        ("size_t", "size"),
    )),
    "flock": ("long", (
        ("unsigned int", "fd"),
        ("unsigned int", "cmd"),
    )),
    "fork": ("long", (
    )),
    "fremovexattr": ("long", (
        ("int", "fd"),
        ("const char *", "name"),
    )),
    "fsetxattr": ("long", (
        ("int", "fd"),
        ("const char *", "name"),
        ("const void *", "value"),
        ("size_t", "size"),
        ("int", "flags"),
    )),
    "fstat": ("long", (
        ("unsigned int", "fd"),
        ("struct __old_kernel_stat *", "statbuf"),
    )),
    "fstat64": ("long", (
        ("unsigned long", "fd"),
        ("struct stat64 *", "statbuf"),
    )),
    "fstatat64": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("struct stat64 *", "statbuf"),
        ("int", "flag"),
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
    "fsync": ("long", (
        ("unsigned int", "fd"),
    )),
    "ftruncate": ("long", (
        ("unsigned int", "fd"),
        ("unsigned long", "length"),
    )),
    "ftruncate64": ("long", (
        ("unsigned int", "fd"),
        ("loff_t", "length"),
    )),
    "futex": ("long", (
        ("u32 *", "uaddr"),
        ("int", "op"),
        ("u32", "val"),
        ("struct timespec *", "utime"),
        ("u32 *", "uaddr2"),
        ("u32", "val3"),
    )),
    "futimesat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("struct timeval *", "utimes"),
    )),
    "get_mempolicy": ("long", (
        ("int *", "policy"),
        ("unsigned long *", "nmask"),
        ("unsigned long", "maxnode"),
        ("unsigned long", "addr"),
        ("unsigned long", "flags"),
    )),
    "get_robust_list": ("long", (
        ("int", "pid"),
        ("struct robust_list_head * *", "head_ptr"),
        ("size_t *", "len_ptr"),
    )),
    "getcpu": ("long", (
        ("unsigned *", "cpu"),
        ("unsigned *", "node"),
        ("struct getcpu_cache *", "cache"),
    )),
    "getcwd": ("long", (
        ("char *", "pathname"),
        ("unsigned long", "size"),
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
    "getegid": ("long", (
    )),
    "getegid16": ("long", (
    )),
    "geteuid": ("long", (
    )),
    "geteuid16": ("long", (
    )),
    "getgid": ("long", (
    )),
    "getgid16": ("long", (
    )),
    "getgroups": ("long", (
        ("int", "gidsetsize"),
        ("gid_t *", "grouplist"),
    )),
    "getgroups16": ("long", (
        ("int", "gidsetsize"),
        ("old_gid_t *", "grouplist"),
    )),
    "gethostname": ("long", (
        ("char *", "name"),
        ("int", "len"),
    )),
    "getitimer": ("long", (
        ("int", "which"),
        ("struct itimerval *", "value"),
    )),
    "getpeername": ("long", (
        ("int", "sockfd"),
        ("struct sockaddr *", "addr"),
        ("int *", "addrlen"),
    )),
    "getpgid": ("long", (
        ("pid_t", "pid"),
    )),
    "getpgrp": ("long", (
    )),
    "getpid": ("long", (
    )),
    "getppid": ("long", (
    )),
    "getpriority": ("long", (
        ("int", "which"),
        ("int", "who"),
    )),
    "getrandom": ("long", (
        ("char *", "buf"),
        ("size_t", "count"),
        ("unsigned int", "flags"),
    )),
    "getresgid": ("long", (
        ("gid_t *", "rgid"),
        ("gid_t *", "egid"),
        ("gid_t *", "sgid"),
    )),
    "getresgid16": ("long", (
        ("old_gid_t *", "rgid"),
        ("old_gid_t *", "egid"),
        ("old_gid_t *", "sgid"),
    )),
    "getresuid": ("long", (
        ("uid_t *", "ruid"),
        ("uid_t *", "euid"),
        ("uid_t *", "suid"),
    )),
    "getresuid16": ("long", (
        ("old_uid_t *", "ruid"),
        ("old_uid_t *", "euid"),
        ("old_uid_t *", "suid"),
    )),
    "getrlimit": ("long", (
        ("unsigned int", "resource"),
        ("struct rlimit *", "rlim"),
    )),
    "getrusage": ("long", (
        ("int", "who"),
        ("struct rusage *", "ru"),
    )),
    "getsid": ("long", (
        ("pid_t", "pid"),
    )),
    "getsockname": ("long", (
        ("int", "sockfd"),
        ("struct sockaddr *", "addr"),
        ("int *", "addrlen"),
    )),
    "getsockopt": ("long", (
        ("int", "fd"),
        ("int", "level"),
        ("int", "optname"),
        ("char *", "optval"),
        ("int *", "optlen"),
    )),
    "gettid": ("long", (
    )),
    "gettimeofday": ("long", (
        ("struct timeval *", "tv"),
        ("struct timezone *", "tz"),
    )),
    "getuid": ("long", (
    )),
    "getuid16": ("long", (
    )),
    "getxattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
        ("void *", "value"),
        ("size_t", "size"),
    )),
    "init_module": ("long", (
        ("void *", "umod"),
        ("unsigned long", "len"),
        ("const char *", "uargs"),
    )),
    "inotify_add_watch": ("long", (
        ("int", "fd"),
        ("const char *", "path"),
        ("u32", "mask"),
    )),
    "inotify_init": ("long", (
    )),
    "inotify_init1": ("long", (
        ("int", "flags"),
    )),
    "inotify_rm_watch": ("long", (
        ("int", "fd"),
        ("__s32", "wd"),
    )),
    "io_cancel": ("long", (
        ("aio_context_t", "ctx_id"),
        ("struct iocb *", "iocb"),
        ("struct io_event *", "result"),
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
    "io_setup": ("long", (
        ("unsigned", "nr_reqs"),
        ("aio_context_t *", "ctx"),
    )),
    "io_submit": ("long", (
        ("aio_context_t", "ctx_id"),
        ("long", "nr"),
        ("struct iocb * *", "iocbpp"),
    )),
    "ioctl": ("long", (
        ("unsigned int", "fd"),
        ("unsigned int", "cmd"),
        ("unsigned long", "arg"),
    )),
    "ioperm": ("long", (
        ("unsigned long", "from"),
        ("unsigned long", "num"),
        ("int", "on"),
    )),
    "ioprio_get": ("long", (
        ("int", "which"),
        ("int", "who"),
    )),
    "ioprio_set": ("long", (
        ("int", "which"),
        ("int", "who"),
        ("int", "ioprio"),
    )),
    "ipc": ("long", (
        ("unsigned int", "call"),
        ("int", "first"),
        ("unsigned long", "second"),
        ("unsigned long", "third"),
        ("void *", "ptr"),
        ("long", "fifth"),
    )),
    "kcmp": ("long", (
        ("pid_t", "pid1"),
        ("pid_t", "pid2"),
        ("int", "type"),
        ("unsigned long", "idx1"),
        ("unsigned long", "idx2"),
    )),
    "kexec_file_load": ("long", (
        ("int", "kernel_fd"),
        ("int", "initrd_fd"),
        ("unsigned long", "cmdline_len"),
        ("const char *", "cmdline_ptr"),
        ("unsigned long", "flags"),
    )),
    "kexec_load": ("long", (
        ("unsigned long", "entry"),
        ("unsigned long", "nr_segments"),
        ("struct kexec_segment *", "segments"),
        ("unsigned long", "flags"),
    )),
    "keyctl": ("long", (
        ("int", "cmd"),
        ("unsigned long", "arg2"),
        ("unsigned long", "arg3"),
        ("unsigned long", "arg4"),
        ("unsigned long", "arg5"),
    )),
    "kill": ("long", (
        ("int", "pid"),
        ("int", "sig"),
    )),
    "lchown": ("long", (
        ("const char *", "filename"),
        ("uid_t", "user"),
        ("gid_t", "group"),
    )),
    "lchown16": ("long", (
        ("const char *", "filename"),
        ("old_uid_t", "user"),
        ("old_gid_t", "group"),
    )),
    "lgetxattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
        ("void *", "value"),
        ("size_t", "size"),
    )),
    "link": ("long", (
        ("const char *", "oldname"),
        ("const char *", "newname"),
    )),
    "linkat": ("long", (
        ("int", "olddfd"),
        ("const char *", "oldname"),
        ("int", "newdfd"),
        ("const char *", "newname"),
        ("int", "flags"),
    )),
    "listen": ("long", (
        ("int", "sockfd"),
        ("int", "backlog"),
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
    "llseek": ("long", (
        ("unsigned int", "fd"),
        ("unsigned long", "offset_high"),
        ("unsigned long", "offset_low"),
        ("loff_t *", "result"),
        ("unsigned int", "whence"),
    )),
    "lookup_dcookie": ("long", (
        ("u64", "cookie64"),
        ("char *", "buf"),
        ("size_t", "len"),
    )),
    "lremovexattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
    )),
    "lseek": ("long", (
        ("unsigned int", "fd"),
        ("off_t", "offset"),
        ("unsigned int", "whence"),
    )),
    "lsetxattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
        ("const void *", "value"),
        ("size_t", "size"),
        ("int", "flags"),
    )),
    "lstat": ("long", (
        ("const char *", "filename"),
        ("struct __old_kernel_stat *", "statbuf"),
    )),
    "lstat64": ("long", (
        ("const char *", "filename"),
        ("struct stat64 *", "statbuf"),
    )),
    "madvise": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
        ("int", "behavior"),
    )),
    "mbind": ("long", (
        ("unsigned long", "start"),
        ("unsigned long", "len"),
        ("unsigned long", "mode"),
        ("const unsigned long *", "nmask"),
        ("unsigned long", "maxnode"),
        ("unsigned", "flags"),
    )),
    "membarrier": ("long", (
        ("int", "cmd"),
        ("int", "flags"),
    )),
    "memfd_create": ("long", (
        ("const char *", "uname_ptr"),
        ("unsigned int", "flags"),
    )),
    "migrate_pages": ("long", (
        ("pid_t", "pid"),
        ("unsigned long", "maxnode"),
        ("const unsigned long *", "from"),
        ("const unsigned long *", "to"),
    )),
    "mincore": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
        ("unsigned char *", "vec"),
    )),
    "mkdir": ("long", (
        ("const char *", "pathname"),
        ("umode_t", "mode"),
    )),
    "mkdirat": ("long", (
        ("int", "dfd"),
        ("const char *", "pathname"),
        ("umode_t", "mode"),
    )),
    "mknod": ("long", (
        ("const char *", "filename"),
        ("umode_t", "mode"),
        ("unsigned", "dev"),
    )),
    "mknodat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("umode_t", "mode"),
        ("unsigned", "dev"),
    )),
    "mlock": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
    )),
    "mlock2": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
        ("int", "flags"),
    )),
    "mlockall": ("long", (
        ("int", "flags"),
    )),
    "mmap_pgoff": ("long", (
        ("unsigned long", "addr"),
        ("unsigned long", "len"),
        ("unsigned long", "prot"),
        ("unsigned long", "flags"),
        ("unsigned long", "fd"),
        ("unsigned long", "pgoff"),
    )),
    "mount": ("long", (
        ("char *", "dev_name"),
        ("char *", "dir_name"),
        ("char *", "type"),
        ("unsigned long", "flags"),
        ("void *", "data"),
    )),
    "move_pages": ("long", (
        ("pid_t", "pid"),
        ("unsigned long", "nr_pages"),
        ("const void * *", "pages"),
        ("const int *", "nodes"),
        ("int *", "status"),
        ("int", "flags"),
    )),
    "mprotect": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
        ("unsigned long", "prot"),
    )),
    "mq_getsetattr": ("long", (
        ("mqd_t", "mqdes"),
        ("const struct mq_attr *", "mqstat"),
        ("struct mq_attr *", "omqstat"),
    )),
    "mq_notify": ("long", (
        ("mqd_t", "mqdes"),
        ("const struct sigevent *", "notification"),
    )),
    "mq_open": ("long", (
        ("const char *", "name"),
        ("int", "oflag"),
        ("umode_t", "mode"),
        ("struct mq_attr *", "attr"),
    )),
    "mq_timedreceive": ("long", (
        ("mqd_t", "mqdes"),
        ("char *", "msg_ptr"),
        ("size_t", "msg_len"),
        ("unsigned int *", "msg_prio"),
        ("const struct timespec *", "abs_timeout"),
    )),
    "mq_timedsend": ("long", (
        ("mqd_t", "mqdes"),
        ("const char *", "msg_ptr"),
        ("size_t", "msg_len"),
        ("unsigned int", "msg_prio"),
        ("const struct timespec *", "abs_timeout"),
    )),
    "mq_unlink": ("long", (
        ("const char *", "name"),
    )),
    "mremap": ("long", (
        ("unsigned long", "addr"),
        ("unsigned long", "old_len"),
        ("unsigned long", "new_len"),
        ("unsigned long", "flags"),
        ("unsigned long", "new_addr"),
    )),
    "msgctl": ("long", (
        ("int", "msqid"),
        ("int", "cmd"),
        ("struct msqid_ds *", "buf"),
    )),
    "msgget": ("long", (
        ("key_t", "key"),
        ("int", "msgflg"),
    )),
    "msgrcv": ("long", (
        ("int", "msqid"),
        ("struct msgbuf *", "msgp"),
        ("size_t", "msgsz"),
        ("long", "msgtyp"),
        ("int", "msgflg"),
    )),
    "msgsnd": ("long", (
        ("int", "msqid"),
        ("struct msgbuf *", "msgp"),
        ("size_t", "msgsz"),
        ("int", "msgflg"),
    )),
    "msync": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
        ("int", "flags"),
    )),
    "munlock": ("long", (
        ("unsigned long", "start"),
        ("size_t", "len"),
    )),
    "munlockall": ("long", (
    )),
    "munmap": ("long", (
        ("unsigned long", "addr"),
        ("size_t", "len"),
    )),
    "name_to_handle_at": ("long", (
        ("int", "dirfd"),
        ("const char *", "name"),
        ("struct file_handle *", "handle"),
        ("int *", "mnt_id"),
        ("int", "flag"),
    )),
    "nanosleep": ("long", (
        ("struct timespec *", "rqtp"),
        ("struct timespec *", "rmtp"),
    )),
    "newfstat": ("long", (
        ("unsigned int", "fd"),
        ("struct stat *", "statbuf"),
    )),
    "newfstatat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("struct stat *", "statbuf"),
        ("int", "flag"),
    )),
    "newlstat": ("long", (
        ("const char *", "filename"),
        ("struct stat *", "statbuf"),
    )),
    "newstat": ("long", (
        ("const char *", "filename"),
        ("struct stat *", "statbuf"),
    )),
    "newuname": ("long", (
        ("struct new_utsname *", "name"),
    )),
    "ni_syscall": ("long", (
    )),
    "nice": ("long", (
        ("int", "increment"),
    )),
    "old_getrlimit": ("long", (
        ("unsigned int", "resource"),
        ("struct rlimit *", "rlim"),
    )),
    "old_mmap": ("long", (
        ("struct mmap_arg_struct *", "arg"),
    )),
    "old_readdir": ("long", (
        ("unsigned int", "fd"),
        ("struct old_linux_dirent *", "dirp"),
        ("unsigned int", "count"),
    )),
    "old_select": ("long", (
        ("struct sel_arg_struct *", "arg"),
    )),
    "oldumount": ("long", (
        ("char *", "name"),
    )),
    "olduname": ("long", (
        ("struct oldold_utsname *", "buf"),
    )),
    "open": ("long", (
        ("const char *", "filename"),
        ("int", "flags"),
        ("umode_t", "mode"),
    )),
    "open_by_handle_at": ("long", (
        ("int", "mount_fd"),
        ("struct file_handle *", "handle"),
        ("int", "flags"),
    )),
    "openat": ("long", (
        ("int", "dirfd"),
        ("const char *", "filename"),
        ("int", "flags"),
        ("umode_t", "mode"),
    )),
    "pause": ("long", (
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
    "perf_event_open": ("long", (
        ("struct perf_event_attr *", "attr_uptr"),
        ("pid_t", "pid"),
        ("int", "cpu"),
        ("int", "group_fd"),
        ("unsigned long", "flags"),
    )),
    "personality": ("long", (
        ("unsigned int", "personality"),
    )),
    "pipe": ("long", (
        ("int *", "fildes"),
    )),
    "pipe2": ("long", (
        ("int *", "fildes"),
        ("int", "flags"),
    )),
    "pivot_root": ("long", (
        ("const char *", "new_root"),
        ("const char *", "put_old"),
    )),
    "poll": ("long", (
        ("struct pollfd *", "ufds"),
        ("unsigned int", "nfds"),
        ("int", "timeout"),
    )),
    "ppoll": ("long", (
        ("struct pollfd *", "fds"),
        ("unsigned int", "nfds"),
        ("struct timespec *", "tmo_p"),
        ("const sigset_t *", "sigmask"),
        ("size_t", ""),
    )),
    "prctl": ("long", (
        ("int", "option"),
        ("unsigned long", "arg2"),
        ("unsigned long", "arg3"),
        ("unsigned long", "arg4"),
        ("unsigned long", "arg5"),
    )),
    "pread64": ("long", (
        ("unsigned int", "fd"),
        ("char *", "buf"),
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
    "prlimit64": ("long", (
        ("pid_t", "pid"),
        ("unsigned int", "resource"),
        ("const struct rlimit64 *", "new_rlim"),
        ("struct rlimit64 *", "old_rlim"),
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
    "pselect6": ("long", (
        ("int", "nfds"),
        ("fd_set *", "readfds"),
        ("fd_set *", "writefds"),
        ("fd_set *", "exceptfds"),
        ("struct timespec *", "timeout"),
        ("void *", "sigmask"),
    )),
    "ptrace": ("long", (
        ("long", "request"),
        ("long", "pid"),
        ("unsigned long", "addr"),
        ("unsigned long", "data"),
    )),
    "pwrite64": ("long", (
        ("unsigned int", "fd"),
        ("const char *", "buf"),
        ("size_t", "count"),
        ("loff_t", "pos"),
    )),
    "pwritev": ("long", (
        ("unsigned long", "fd"),
        ("const struct iovec *", "vec"),
        ("unsigned long", "vlen"),
        ("unsigned long", "pos_l"),
        ("unsigned long", "pos_h"),
    )),
    "quotactl": ("long", (
        ("unsigned int", "cmd"),
        ("const char *", "special"),
        ("qid_t", "id"),
        ("void *", "addr"),
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
    "readlink": ("long", (
        ("const char *", "path"),
        ("char *", "buf"),
        ("int", "bufsiz"),
    )),
    "readlinkat": ("long", (
        ("int", "dfd"),
        ("const char *", "path"),
        ("char *", "buf"),
        ("int", "bufsiz"),
    )),
    "readv": ("long", (
        ("unsigned long", "fd"),
        ("const struct iovec *", "vec"),
        ("unsigned long", "vlen"),
    )),
    "reboot": ("long", (
        ("int", "magic1"),
        ("int", "magic2"),
        ("unsigned int", "cmd"),
        ("void *", "arg"),
    )),
    "recv": ("long", (
        ("int", "sockfd"),
        ("void *", "buf"),
        ("size_t", "len"),
        ("unsigned", "flags"),
    )),
    "recvfrom": ("long", (
        ("int", "sockfd"),
        ("void *", "buf"),
        ("size_t", "len"),
        ("unsigned", "flags"),
        ("struct sockaddr *", "src_addr"),
        ("int *", "addrlen"),
    )),
    "recvmmsg": ("long", (
        ("int", "fd"),
        ("struct mmsghdr *", "msg"),
        ("unsigned int", "vlen"),
        ("unsigned", "flags"),
        ("struct timespec *", "timeout"),
    )),
    "recvmsg": ("long", (
        ("int", "fd"),
        ("struct user_msghdr *", "msg"),
        ("unsigned", "flags"),
    )),
    "remap_file_pages": ("long", (
        ("unsigned long", "start"),
        ("unsigned long", "size"),
        ("unsigned long", "prot"),
        ("unsigned long", "pgoff"),
        ("unsigned long", "flags"),
    )),
    "removexattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
    )),
    "rename": ("long", (
        ("const char *", "oldname"),
        ("const char *", "newname"),
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
    "request_key": ("long", (
        ("const char *", "_type"),
        ("const char *", "_description"),
        ("const char *", "_callout_info"),
        ("key_serial_t", "destringid"),
    )),
    "restart_syscall": ("long", (
    )),
    "rmdir": ("long", (
        ("const char *", "pathname"),
    )),
    "rt_sigaction": ("long", (
        ("int", "signum"),
        ("const struct sigaction *", "act"),
        ("struct sigaction *", "oldact"),
        ("size_t", ""),
    )),
    "rt_sigpending": ("long", (
        ("sigset_t *", "set"),
        ("size_t", "sigsetsize"),
    )),
    "rt_sigprocmask": ("long", (
        ("int", "how"),
        ("sigset_t *", "set"),
        ("sigset_t *", "oset"),
        ("size_t", "sigsetsize"),
    )),
    "rt_sigqueueinfo": ("long", (
        ("int", "pid"),
        ("int", "sig"),
        ("siginfo_t *", "uinfo"),
    )),
    "rt_sigsuspend": ("long", (
        ("sigset_t *", "unewset"),
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
    "sched_get_priority_max": ("long", (
        ("int", "policy"),
    )),
    "sched_get_priority_min": ("long", (
        ("int", "policy"),
    )),
    "sched_getaffinity": ("long", (
        ("pid_t", "pid"),
        ("unsigned int", "len"),
        ("unsigned long *", "user_mask_ptr"),
    )),
    "sched_getattr": ("long", (
        ("pid_t", "pid"),
        ("struct sched_attr *", "attr"),
        ("unsigned int", "size"),
        ("unsigned int", "flags"),
    )),
    "sched_getparam": ("long", (
        ("pid_t", "pid"),
        ("struct sched_param *", "param"),
    )),
    "sched_getscheduler": ("long", (
        ("pid_t", "pid"),
    )),
    "sched_rr_get_interval": ("long", (
        ("pid_t", "pid"),
        ("struct timespec *", "interval"),
    )),
    "sched_setaffinity": ("long", (
        ("pid_t", "pid"),
        ("unsigned int", "len"),
        ("unsigned long *", "user_mask_ptr"),
    )),
    "sched_setattr": ("long", (
        ("pid_t", "pid"),
        ("struct sched_attr *", "attr"),
        ("unsigned int", "flags"),
    )),
    "sched_setparam": ("long", (
        ("pid_t", "pid"),
        ("struct sched_param *", "param"),
    )),
    "sched_setscheduler": ("long", (
        ("pid_t", "pid"),
        ("int", "policy"),
        ("struct sched_param *", "param"),
    )),
    "sched_yield": ("long", (
    )),
    "seccomp": ("long", (
        ("unsigned int", "op"),
        ("unsigned int", "flags"),
        ("const char *", "uargs"),
    )),
    "select": ("long", (
        ("int", "nfds"),
        ("fd_set *", "readfds"),
        ("fd_set *", "writefds"),
        ("fd_set *", "errorfds"),
        ("struct timeval *", "timeout"),
    )),
    "semctl": ("long", (
        ("int", "semid"),
        ("int", "semnum"),
        ("int", "cmd"),
        ("unsigned long", "arg"),
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
    "semtimedop": ("long", (
        ("int", "semid"),
        ("struct sembuf *", "sops"),
        ("unsigned", "nsops"),
        ("const struct timespec *", "timeout"),
    )),
    "send": ("long", (
        ("int", "sockfd"),
        ("void *", "buf"),
        ("size_t", "len"),
        ("unsigned", "flags"),
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
    "sendmmsg": ("long", (
        ("int", "fd"),
        ("struct mmsghdr *", "msg"),
        ("unsigned int", "vlen"),
        ("unsigned", "flags"),
    )),
    "sendmsg": ("long", (
        ("int", "fd"),
        ("struct user_msghdr *", "msg"),
        ("unsigned", "flags"),
    )),
    "sendto": ("long", (
        ("int", "sockfd"),
        ("void *", "buf"),
        ("size_t", "len"),
        ("unsigned", "flags"),
        ("struct sockaddr *", "dest_addr"),
        ("int", "addrlen"),
    )),
    "set_mempolicy": ("long", (
        ("int", "mode"),
        ("const unsigned long *", "nmask"),
        ("unsigned long", "maxnode"),
    )),
    "set_robust_list": ("long", (
        ("struct robust_list_head *", "head"),
        ("size_t", "len"),
    )),
    "set_tid_address": ("long", (
        ("int *", "tidptr"),
    )),
    "setdomainname": ("long", (
        ("char *", "name"),
        ("int", "len"),
    )),
    "setfsgid": ("long", (
        ("gid_t", "gid"),
    )),
    "setfsgid16": ("long", (
        ("old_gid_t", "gid"),
    )),
    "setfsuid": ("long", (
        ("uid_t", "uid"),
    )),
    "setfsuid16": ("long", (
        ("old_uid_t", "uid"),
    )),
    "setgid": ("long", (
        ("gid_t", "gid"),
    )),
    "setgid16": ("long", (
        ("old_gid_t", "gid"),
    )),
    "setgroups": ("long", (
        ("int", "gidsetsize"),
        ("gid_t *", "grouplist"),
    )),
    "setgroups16": ("long", (
        ("int", "gidsetsize"),
        ("old_gid_t *", "grouplist"),
    )),
    "sethostname": ("long", (
        ("char *", "name"),
        ("int", "len"),
    )),
    "setitimer": ("long", (
        ("int", "which"),
        ("struct itimerval *", "value"),
        ("struct itimerval *", "ovalue"),
    )),
    "setns": ("long", (
        ("int", "fd"),
        ("int", "nstype"),
    )),
    "setpgid": ("long", (
        ("pid_t", "pid"),
        ("pid_t", "pgid"),
    )),
    "setpriority": ("long", (
        ("int", "which"),
        ("int", "who"),
        ("int", "niceval"),
    )),
    "setregid": ("long", (
        ("gid_t", "rgid"),
        ("gid_t", "egid"),
    )),
    "setregid16": ("long", (
        ("old_gid_t", "rgid"),
        ("old_gid_t", "egid"),
    )),
    "setresgid": ("long", (
        ("gid_t", "rgid"),
        ("gid_t", "egid"),
        ("gid_t", "sgid"),
    )),
    "setresgid16": ("long", (
        ("old_gid_t", "rgid"),
        ("old_gid_t", "egid"),
        ("old_gid_t", "sgid"),
    )),
    "setresuid": ("long", (
        ("uid_t", "ruid"),
        ("uid_t", "euid"),
        ("uid_t", "suid"),
    )),
    "setresuid16": ("long", (
        ("old_uid_t", "ruid"),
        ("old_uid_t", "euid"),
        ("old_uid_t", "suid"),
    )),
    "setreuid": ("long", (
        ("uid_t", "ruid"),
        ("uid_t", "euid"),
    )),
    "setreuid16": ("long", (
        ("old_uid_t", "ruid"),
        ("old_uid_t", "euid"),
    )),
    "setrlimit": ("long", (
        ("unsigned int", "resource"),
        ("struct rlimit *", "rlim"),
    )),
    "setsid": ("long", (
    )),
    "setsockopt": ("long", (
        ("int", "fd"),
        ("int", "level"),
        ("int", "optname"),
        ("char *", "optval"),
        ("int", "optlen"),
    )),
    "settimeofday": ("long", (
        ("struct timeval *", "tv"),
        ("struct timezone *", "tz"),
    )),
    "setuid": ("long", (
        ("uid_t", "uid"),
    )),
    "setuid16": ("long", (
        ("old_uid_t", "uid"),
    )),
    "setxattr": ("long", (
        ("const char *", "path"),
        ("const char *", "name"),
        ("const void *", "value"),
        ("size_t", "size"),
        ("int", "flags"),
    )),
    "sgetmask": ("long", (
    )),
    "shmat": ("long", (
        ("int", "shmid"),
        ("char *", "shmaddr"),
        ("int", "shmflg"),
    )),
    "shmctl": ("long", (
        ("int", "shmid"),
        ("int", "cmd"),
        ("struct shmid_ds *", "buf"),
    )),
    "shmdt": ("long", (
        ("char *", "shmaddr"),
    )),
    "shmget": ("long", (
        ("key_t", "key"),
        ("size_t", "size"),
        ("int", "flag"),
    )),
    "shutdown": ("long", (
        ("int", "sockfd"),
        ("int", "how"),
    )),
    "sigaction": ("long", (
        ("int", "signum"),
        ("const struct old_sigaction *", "act"),
        ("struct old_sigaction *", "oldact"),
    )),
    "sigaltstack": ("long", (
        ("const struct sigaltstack *", "uss"),
        ("struct sigaltstack *", "uoss"),
    )),
    "signal": ("long", (
        ("int", "sig"),
        ("__sighandler_t", "handler"),
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
    "sigpending": ("long", (
        ("old_sigset_t *", "set"),
    )),
    "sigprocmask": ("long", (
        ("int", "how"),
        ("old_sigset_t *", "set"),
        ("old_sigset_t *", "oset"),
    )),
    "sigsuspend": ("long", (
        ("int", "unused1"),
        ("int", "unused2"),
        ("old_sigset_t", "mask"),
    )),
    "socket": ("long", (
        ("int", "domain"),
        ("int", "type"),
        ("int", "protocol"),
    )),
    "socketcall": ("long", (
        ("int", "call"),
        ("unsigned long *", "args"),
    )),
    "socketpair": ("long", (
        ("int", "domain"),
        ("int", "type"),
        ("int", "protocol"),
        ("int *", "sv"),
    )),
    "splice": ("long", (
        ("int", "fd_in"),
        ("loff_t *", "off_in"),
        ("int", "fd_out"),
        ("loff_t *", "off_out"),
        ("size_t", "len"),
        ("unsigned int", "flags"),
    )),
    "spu_create": ("long", (
        ("const char *", "name"),
        ("unsigned int", "flags"),
        ("umode_t", "mode"),
        ("int", "fd"),
    )),
    "spu_run": ("long", (
        ("int", "fd"),
        ("__u32 *", "unpc"),
        ("__u32 *", "ustatus"),
    )),
    "ssetmask": ("long", (
        ("int", "newmask"),
    )),
    "stat": ("long", (
        ("const char *", "filename"),
        ("struct __old_kernel_stat *", "statbuf"),
    )),
    "stat64": ("long", (
        ("const char *", "filename"),
        ("struct stat64 *", "statbuf"),
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
    "statx": ("long", (
        ("int", "dirfd"),
        ("const char *", "pathname"),
        ("int", "flags"),
        ("unsigned int", "mask"),
        ("struct statx *", "statxbuf"),
    )),
    "stime": ("long", (
        ("time_t *", "tptr"),
    )),
    "swapoff": ("long", (
        ("const char *", "specialfile"),
    )),
    "swapon": ("long", (
        ("const char *", "specialfile"),
        ("int", "swap_flags"),
    )),
    "symlink": ("long", (
        ("const char *", "old"),
        ("const char *", "new"),
    )),
    "symlinkat": ("long", (
        ("const char *", "oldname"),
        ("int", "newdfd"),
        ("const char *", "newname"),
    )),
    "sync": ("long", (
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
    "syncfs": ("long", (
        ("int", "fd"),
    )),
    "sysctl": ("long", (
        ("struct __sysctl_args *", "args"),
    )),
    "sysfs": ("long", (
        ("int", "option"),
        ("unsigned long", "arg1"),
        ("unsigned long", "arg2"),
    )),
    "sysinfo": ("long", (
        ("struct sysinfo *", "info"),
    )),
    "syslog": ("long", (
        ("int", "type"),
        ("char *", "buf"),
        ("int", "len"),
    )),
    "tee": ("long", (
        ("int", "fdin"),
        ("int", "fdout"),
        ("size_t", "len"),
        ("unsigned int", "flags"),
    )),
    "tgkill": ("long", (
        ("int", "tgid"),
        ("int", "pid"),
        ("int", "sig"),
    )),
    "time": ("long", (
        ("time_t *", "tloc"),
    )),
    "timer_create": ("long", (
        ("clockid_t", "which_clock"),
        ("struct sigevent *", "timer_event_spec"),
        ("timer_t *", "created_timer_id"),
    )),
    "timer_delete": ("long", (
        ("timer_t", "timer_id"),
    )),
    "timer_getoverrun": ("long", (
        ("timer_t", "timer_id"),
    )),
    "timer_gettime": ("long", (
        ("timer_t", "timer_id"),
        ("struct itimerspec *", "setting"),
    )),
    "timer_settime": ("long", (
        ("timer_t", "timer_id"),
        ("int", "flags"),
        ("const struct itimerspec *", "new_setting"),
        ("struct itimerspec *", "old_setting"),
    )),
    "timerfd_create": ("long", (
        ("int", "clockid"),
        ("int", "flags"),
    )),
    "timerfd_gettime": ("long", (
        ("int", "ufd"),
        ("struct itimerspec *", "otmr"),
    )),
    "timerfd_settime": ("long", (
        ("int", "ufd"),
        ("int", "flags"),
        ("const struct itimerspec *", "utmr"),
        ("struct itimerspec *", "otmr"),
    )),
    "times": ("long", (
        ("struct tms *", "tbuf"),
    )),
    "tkill": ("long", (
        ("int", "pid"),
        ("int", "sig"),
    )),
    "truncate": ("long", (
        ("const char *", "path"),
        ("long", "length"),
    )),
    "truncate64": ("long", (
        ("const char *", "path"),
        ("loff_t", "length"),
    )),
    "umask": ("long", (
        ("int", "mask"),
    )),
    "umount": ("long", (
        ("char *", "name"),
        ("int", "flags"),
    )),
    "uname": ("long", (
        ("struct old_utsname *", "buf"),
    )),
    "unlink": ("long", (
        ("const char *", "pathname"),
    )),
    "unlinkat": ("long", (
        ("int", "dfd"),
        ("const char *", "pathname"),
        ("int", "flag"),
    )),
    "unshare": ("long", (
        ("unsigned long", "unshare_flags"),
    )),
    "uselib": ("long", (
        ("const char *", "library"),
    )),
    "userfaultfd": ("long", (
        ("int", "flags"),
    )),
    "ustat": ("long", (
        ("unsigned", "dev"),
        ("struct ustat *", "ubuf"),
    )),
    "utime": ("long", (
        ("char *", "filename"),
        ("struct utimbuf *", "times"),
    )),
    "utimensat": ("long", (
        ("int", "dfd"),
        ("const char *", "filename"),
        ("struct timespec *", "utimes"),
        ("int", "flags"),
    )),
    "utimes": ("long", (
        ("char *", "filename"),
        ("struct timeval *", "utimes"),
    )),
    "vfork": ("long", (
    )),
    "vhangup": ("long", (
    )),
    "vmsplice": ("long", (
        ("int", "fd"),
        ("const struct iovec *", "iov"),
        ("unsigned long", "nr_segs"),
        ("unsigned int", "flags"),
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
}

for orig, copies in ALIASES.items():
    orig = SYSCALL_PROTOTYPES[orig]
    for copy in copies:
        SYSCALL_PROTOTYPES[copy] = orig
