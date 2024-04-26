#![allow(non_upper_case_globals)]
/// `long sys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx);`
pub const io_setup: u64 = 0;
/// `long sys_io_destroy(aio_context_t ctx);`
pub const io_destroy: u64 = 1;
/// `long sys_io_submit(aio_context_t, long, struct iocb __user * __user *);`
pub const io_submit: u64 = 2;
/// `long sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result);`
pub const io_cancel: u64 = 3;
/// `long sys_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout);`
pub const io_getevents: u64 = 4;
/// `long sys_setxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);`
pub const setxattr: u64 = 5;
/// `long sys_lsetxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);`
pub const lsetxattr: u64 = 6;
/// `long sys_fsetxattr(int fd, const char __user *name, const void __user *value, size_t size, int flags);`
pub const fsetxattr: u64 = 7;
/// `long sys_getxattr(const char __user *path, const char __user *name, void __user *value, size_t size);`
pub const getxattr: u64 = 8;
/// `long sys_lgetxattr(const char __user *path, const char __user *name, void __user *value, size_t size);`
pub const lgetxattr: u64 = 9;
/// `long sys_fgetxattr(int fd, const char __user *name, void __user *value, size_t size);`
pub const fgetxattr: u64 = 10;
/// `long sys_listxattr(const char __user *path, char __user *list, size_t size);`
pub const listxattr: u64 = 11;
/// `long sys_llistxattr(const char __user *path, char __user *list, size_t size);`
pub const llistxattr: u64 = 12;
/// `long sys_flistxattr(int fd, char __user *list, size_t size);`
pub const flistxattr: u64 = 13;
/// `long sys_removexattr(const char __user *path, const char __user *name);`
pub const removexattr: u64 = 14;
/// `long sys_lremovexattr(const char __user *path, const char __user *name);`
pub const lremovexattr: u64 = 15;
/// `long sys_fremovexattr(int fd, const char __user *name);`
pub const fremovexattr: u64 = 16;
/// `long sys_getcwd(char __user *buf, unsigned long size);`
pub const getcwd: u64 = 17;
/// `long sys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len);`
pub const lookup_dcookie: u64 = 18;
/// `long sys_eventfd2(unsigned int count, int flags);`
pub const eventfd2: u64 = 19;
/// `long sys_epoll_create1(int flags);`
pub const epoll_create1: u64 = 20;
/// `long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event);`
pub const epoll_ctl: u64 = 21;
/// `long sys_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize);`
pub const epoll_pwait: u64 = 22;
/// `long sys_dup(unsigned int fildes);`
pub const dup: u64 = 23;
/// `long sys_dup3(unsigned int oldfd, unsigned int newfd, int flags);`
pub const dup3: u64 = 24;
/// `long sys_fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg);`
pub const fcntl64: u64 = 25;
/// `long sys_inotify_init1(int flags);`
pub const inotify_init1: u64 = 26;
/// `long sys_inotify_add_watch(int fd, const char __user *path, u32 mask);`
pub const inotify_add_watch: u64 = 27;
/// `long sys_inotify_rm_watch(int fd, __s32 wd);`
pub const inotify_rm_watch: u64 = 28;
/// `long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);`
pub const ioctl: u64 = 29;
/// `long sys_ioprio_set(int which, int who, int ioprio);`
pub const ioprio_set: u64 = 30;
/// `long sys_ioprio_get(int which, int who);`
pub const ioprio_get: u64 = 31;
/// `long sys_flock(unsigned int fd, unsigned int cmd);`
pub const flock: u64 = 32;
/// `long sys_mknodat(int dfd, const char __user * filename, umode_t mode, unsigned dev);`
pub const mknodat: u64 = 33;
/// `long sys_mkdirat(int dfd, const char __user * pathname, umode_t mode);`
pub const mkdirat: u64 = 34;
/// `long sys_unlinkat(int dfd, const char __user * pathname, int flag);`
pub const unlinkat: u64 = 35;
/// `long sys_symlinkat(const char __user * oldname, int newdfd, const char __user * newname);`
pub const symlinkat: u64 = 36;
/// `long sys_unlinkat(int dfd, const char __user * pathname, int flag);`
pub const linkat: u64 = 37;
/// `long sys_renameat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname);`
pub const renameat: u64 = 38;
/// `long sys_umount(char __user *name, int flags);`
pub const umount: u64 = 39;
/// `long sys_umount(char __user *name, int flags);`
pub const mount: u64 = 40;
/// `long sys_pivot_root(const char __user *new_root, const char __user *put_old);`
pub const pivot_root: u64 = 41;
/// `long sys_ni_syscall(void);`
pub const ni_syscall: u64 = 42;
/// `long sys_statfs64(const char __user *path, size_t sz, struct statfs64 __user *buf);`
pub const statfs64: u64 = 43;
/// `long sys_fstatfs64(unsigned int fd, size_t sz, struct statfs64 __user *buf);`
pub const fstatfs64: u64 = 44;
/// `long sys_truncate64(const char __user *path, loff_t length);`
pub const truncate64: u64 = 45;
/// `long sys_ftruncate64(unsigned int fd, loff_t length);`
pub const ftruncate64: u64 = 46;
/// `long sys_fallocate(int fd, int mode, loff_t offset, loff_t len);`
pub const fallocate: u64 = 47;
/// `long sys_faccessat(int dfd, const char __user *filename, int mode);`
pub const faccessat: u64 = 48;
/// `long sys_chdir(const char __user *filename);`
pub const chdir: u64 = 49;
/// `long sys_fchdir(unsigned int fd);`
pub const fchdir: u64 = 50;
/// `long sys_chroot(const char __user *filename);`
pub const chroot: u64 = 51;
/// `long sys_fchmod(unsigned int fd, umode_t mode);`
pub const fchmod: u64 = 52;
/// `long sys_fchmodat(int dfd, const char __user * filename, umode_t mode);`
pub const fchmodat: u64 = 53;
/// `long sys_fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag);`
pub const fchownat: u64 = 54;
/// `long sys_fchown(unsigned int fd, uid_t user, gid_t group);`
pub const fchown: u64 = 55;
/// `long sys_openat(int dfd, const char __user *filename, int flags, umode_t mode);`
pub const openat: u64 = 56;
/// `long sys_close(unsigned int fd);`
pub const close: u64 = 57;
/// `long sys_vhangup(void);`
pub const vhangup: u64 = 58;
/// `long sys_pipe2(int __user *fildes, int flags);`
pub const pipe2: u64 = 59;
/// `long sys_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr);`
pub const quotactl: u64 = 60;
/// `long sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);`
pub const getdents64: u64 = 61;
/// `long sys_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int whence);`
pub const lseek: u64 = 62;
/// `long sys_read(unsigned int fd, char __user *buf, size_t count);`
pub const read: u64 = 63;
/// `long sys_write(unsigned int fd, const char __user *buf, size_t count);`
pub const write: u64 = 64;
/// `long sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);`
pub const readv: u64 = 65;
/// `long sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);`
pub const writev: u64 = 66;
/// `long sys_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos);`
pub const pread64: u64 = 67;
/// `long sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);`
pub const pwrite64: u64 = 68;
/// `long sys_preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);`
pub const preadv: u64 = 69;
/// `long sys_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);`
pub const pwritev: u64 = 70;
/// `long sys_sendfile64(int out_fd, int in_fd, loff_t __user *offset, size_t count);`
pub const sendfile64: u64 = 71;
/// `long sys_pselect6_time32(int, fd_set __user *, fd_set __user *, fd_set __user *, struct old_timespec32 __user *, void __user *);`
pub const pselect6_time32: u64 = 72;
/// `long sys_ppoll_time32(struct pollfd __user *, unsigned int, struct old_timespec32 __user *, const sigset_t __user *, size_t);`
pub const ppoll_time32: u64 = 73;
/// `long sys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags);`
pub const signalfd4: u64 = 74;
/// `long sys_vmsplice(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags);`
pub const vmsplice: u64 = 75;
/// `long sys_vmsplice(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags);`
pub const splice: u64 = 76;
/// `long sys_tee(int fdin, int fdout, size_t len, unsigned int flags);`
pub const tee: u64 = 77;
/// `long sys_readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz);`
pub const readlinkat: u64 = 78;
/// `long sys_newfstatat(int dfd, const char __user *filename, struct stat __user *statbuf, int flag);`
pub const newfstatat: u64 = 79;
/// `long sys_newfstat(unsigned int fd, struct stat __user *statbuf);`
pub const newfstat: u64 = 80;
/// `long sys_sync(void);`
pub const sync: u64 = 81;
/// `long sys_fsync(unsigned int fd);`
pub const fsync: u64 = 82;
/// `long sys_fdatasync(unsigned int fd);`
pub const fdatasync: u64 = 83;
/// `long sys_sync_file_range2(int fd, unsigned int flags, loff_t offset, loff_t nbytes);`
pub const sync_file_range2: u64 = 84;
/// `long sys_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags);`
pub const sync_file_range: u64 = 84;
/// `long sys_timerfd_create(int clockid, int flags);`
pub const timerfd_create: u64 = 85;
/// `long sys_timerfd_settime(int ufd, int flags, const struct __kernel_itimerspec __user *utmr, struct __kernel_itimerspec __user *otmr);`
pub const timerfd_settime: u64 = 86;
/// `long sys_timerfd_gettime(int ufd, struct __kernel_itimerspec __user *otmr);`
pub const timerfd_gettime: u64 = 87;
/// `long sys_utimensat(int dfd, const char __user *filename, struct __kernel_timespec __user *utimes, int flags);`
pub const utimensat: u64 = 88;
/// `long sys_acct(const char __user *name);`
pub const acct: u64 = 89;
/// `long sys_capget(cap_user_header_t header, cap_user_data_t dataptr);`
pub const capget: u64 = 90;
/// `long sys_capset(cap_user_header_t header, const cap_user_data_t data);`
pub const capset: u64 = 91;
/// `long sys_personality(unsigned int personality);`
pub const personality: u64 = 92;
/// `long sys_exit(int error_code);`
pub const exit: u64 = 93;
/// `long sys_exit_group(int error_code);`
pub const exit_group: u64 = 94;
/// `long sys_waitid(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru);`
pub const waitid: u64 = 95;
/// `long sys_set_tid_address(int __user *tidptr);`
pub const set_tid_address: u64 = 96;
/// `long sys_unshare(unsigned long unshare_flags);`
pub const unshare: u64 = 97;
/// `long sys_futex(u32 __user *uaddr, int op, u32 val, struct __kernel_timespec __user *utime, u32 __user *uaddr2, u32 val3);`
pub const futex: u64 = 98;
/// `long sys_set_robust_list(struct robust_list_head __user *head, size_t len);`
pub const set_robust_list: u64 = 99;
/// `long sys_get_robust_list(int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr);`
pub const get_robust_list: u64 = 100;
/// `long sys_nanosleep(struct __kernel_timespec __user *rqtp, struct __kernel_timespec __user *rmtp);`
pub const nanosleep: u64 = 101;
/// `long sys_getitimer(int which, struct __kernel_old_itimerval __user *value);`
pub const getitimer: u64 = 102;
/// `long sys_setitimer(int which, struct __kernel_old_itimerval __user *value, struct __kernel_old_itimerval __user *ovalue);`
pub const setitimer: u64 = 103;
/// `long sys_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags);`
pub const kexec_load: u64 = 104;
/// `long sys_init_module(void __user *umod, unsigned long len, const char __user *uargs);`
pub const init_module: u64 = 105;
/// `long sys_delete_module(const char __user *name_user, unsigned int flags);`
pub const delete_module: u64 = 106;
/// `long sys_timer_create(clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id);`
pub const timer_create: u64 = 107;
/// `long sys_timer_gettime(timer_t timer_id, struct __kernel_itimerspec __user *setting);`
pub const timer_gettime: u64 = 108;
/// `long sys_timer_getoverrun(timer_t timer_id);`
pub const timer_getoverrun: u64 = 109;
/// `long sys_timer_settime(timer_t timer_id, int flags, const struct __kernel_itimerspec __user *new_setting, struct __kernel_itimerspec __user *old_setting);`
pub const timer_settime: u64 = 110;
/// `long sys_timer_delete(timer_t timer_id);`
pub const timer_delete: u64 = 111;
/// `long sys_clock_settime(clockid_t which_clock, const struct __kernel_timespec __user *tp);`
pub const clock_settime: u64 = 112;
/// `long sys_clock_gettime(clockid_t which_clock, struct __kernel_timespec __user *tp);`
pub const clock_gettime: u64 = 113;
/// `long sys_clock_getres(clockid_t which_clock, struct __kernel_timespec __user *tp);`
pub const clock_getres: u64 = 114;
/// `long sys_clock_nanosleep(clockid_t which_clock, int flags, const struct __kernel_timespec __user *rqtp, struct __kernel_timespec __user *rmtp);`
pub const clock_nanosleep: u64 = 115;
/// `long sys_syslog(int type, char __user *buf, int len);`
pub const syslog: u64 = 116;
/// `long sys_ptrace(long request, long pid, unsigned long addr, unsigned long data);`
pub const ptrace: u64 = 117;
/// `long sys_sched_setparam(pid_t pid, struct sched_param __user *param);`
pub const sched_setparam: u64 = 118;
/// `long sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param);`
pub const sched_setscheduler: u64 = 119;
/// `long sys_sched_getscheduler(pid_t pid);`
pub const sched_getscheduler: u64 = 120;
/// `long sys_sched_getparam(pid_t pid, struct sched_param __user *param);`
pub const sched_getparam: u64 = 121;
/// `long sys_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);`
pub const sched_setaffinity: u64 = 122;
/// `long sys_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);`
pub const sched_getaffinity: u64 = 123;
/// `long sys_sched_yield(void);`
pub const sched_yield: u64 = 124;
/// `long sys_sched_get_priority_max(int policy);`
pub const sched_get_priority_max: u64 = 125;
/// `long sys_sched_get_priority_min(int policy);`
pub const sched_get_priority_min: u64 = 126;
/// `long sys_sched_rr_get_interval(pid_t pid, struct __kernel_timespec __user *interval);`
pub const sched_rr_get_interval: u64 = 127;
/// `long sys_restart_syscall(void);`
pub const restart_syscall: u64 = 128;
/// `long sys_kill(pid_t pid, int sig);`
pub const kill: u64 = 129;
/// `long sys_tkill(pid_t pid, int sig);`
pub const tkill: u64 = 130;
/// `long sys_tgkill(pid_t tgid, pid_t pid, int sig);`
pub const tgkill: u64 = 131;
/// `long sys_sigaltstack(const struct sigaltstack __user *uss, struct sigaltstack __user *uoss);`
pub const sigaltstack: u64 = 132;
/// `long sys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize);`
pub const rt_sigsuspend: u64 = 133;
/// `long sys_rt_sigaction(int, const struct sigaction __user *, struct sigaction __user *, size_t);`
pub const rt_sigaction: u64 = 134;
/// `long sys_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize);`
pub const rt_sigprocmask: u64 = 135;
/// `long sys_rt_sigpending(sigset_t __user *set, size_t sigsetsize);`
pub const rt_sigpending: u64 = 136;
/// `long sys_rt_sigtimedwait_time32(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct old_timespec32 __user *uts, size_t sigsetsize);`
pub const rt_sigtimedwait_time32: u64 = 137;
/// `long sys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo);`
pub const rt_sigqueueinfo: u64 = 138;
/// `long sys_setpriority(int which, int who, int niceval);`
pub const setpriority: u64 = 140;
/// `long sys_getpriority(int which, int who);`
pub const getpriority: u64 = 141;
/// `long sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg);`
pub const reboot: u64 = 142;
/// `long sys_setregid(gid_t rgid, gid_t egid);`
pub const setregid: u64 = 143;
/// `long sys_setgid(gid_t gid);`
pub const setgid: u64 = 144;
/// `long sys_setreuid(uid_t ruid, uid_t euid);`
pub const setreuid: u64 = 145;
/// `long sys_setuid(uid_t uid);`
pub const setuid: u64 = 146;
/// `long sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);`
pub const setresuid: u64 = 147;
/// `long sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid);`
pub const getresuid: u64 = 148;
/// `long sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid);`
pub const setresgid: u64 = 149;
/// `long sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid);`
pub const getresgid: u64 = 150;
/// `long sys_setfsuid(uid_t uid);`
pub const setfsuid: u64 = 151;
/// `long sys_setfsgid(gid_t gid);`
pub const setfsgid: u64 = 152;
/// `long sys_times(struct tms __user *tbuf);`
pub const times: u64 = 153;
/// `long sys_setpgid(pid_t pid, pid_t pgid);`
pub const setpgid: u64 = 154;
/// `long sys_getpgid(pid_t pid);`
pub const getpgid: u64 = 155;
/// `long sys_getsid(pid_t pid);`
pub const getsid: u64 = 156;
/// `long sys_setsid(void);`
pub const setsid: u64 = 157;
/// `long sys_getgroups(int gidsetsize, gid_t __user *grouplist);`
pub const getgroups: u64 = 158;
/// `long sys_setgroups(int gidsetsize, gid_t __user *grouplist);`
pub const setgroups: u64 = 159;
/// `long sys_newuname(struct new_utsname __user *name);`
pub const newuname: u64 = 160;
/// `long sys_sethostname(char __user *name, int len);`
pub const sethostname: u64 = 161;
/// `long sys_setdomainname(char __user *name, int len);`
pub const setdomainname: u64 = 162;
/// `long sys_getrlimit(unsigned int resource, struct rlimit __user *rlim);`
pub const getrlimit: u64 = 163;
/// `long sys_setrlimit(unsigned int resource, struct rlimit __user *rlim);`
pub const setrlimit: u64 = 164;
/// `long sys_getrusage(int who, struct rusage __user *ru);`
pub const getrusage: u64 = 165;
/// `long sys_umask(int mask);`
pub const umask: u64 = 166;
/// `long sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);`
pub const prctl: u64 = 167;
/// `long sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache);`
pub const getcpu: u64 = 168;
/// `long sys_gettimeofday(struct __kernel_old_timeval __user *tv, struct timezone __user *tz);`
pub const gettimeofday: u64 = 169;
/// `long sys_settimeofday(struct __kernel_old_timeval __user *tv, struct timezone __user *tz);`
pub const settimeofday: u64 = 170;
/// `long sys_adjtimex(struct __kernel_timex __user *txc_p);`
pub const adjtimex: u64 = 171;
/// `long sys_getpid(void);`
pub const getpid: u64 = 172;
/// `long sys_getppid(void);`
pub const getppid: u64 = 173;
/// `long sys_getuid(void);`
pub const getuid: u64 = 174;
/// `long sys_geteuid(void);`
pub const geteuid: u64 = 175;
/// `long sys_getgid(void);`
pub const getgid: u64 = 176;
/// `long sys_getegid(void);`
pub const getegid: u64 = 177;
/// `long sys_gettid(void);`
pub const gettid: u64 = 178;
/// `long sys_sysinfo(struct sysinfo __user *info);`
pub const sysinfo: u64 = 179;
/// `long sys_mq_open(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr);`
pub const mq_open: u64 = 180;
/// `long sys_mq_unlink(const char __user *name);`
pub const mq_unlink: u64 = 181;
/// `long sys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec __user *abs_timeout);`
pub const mq_timedsend: u64 = 182;
/// `long sys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct __kernel_timespec __user *abs_timeout);`
pub const mq_timedreceive: u64 = 183;
/// `long sys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification);`
pub const mq_notify: u64 = 184;
/// `long sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat);`
pub const mq_getsetattr: u64 = 185;
/// `long sys_msgget(key_t key, int msgflg);`
pub const msgget: u64 = 186;
/// `long sys_old_msgctl(int msqid, int cmd, struct msqid_ds __user *buf);`
pub const msgctl: u64 = 187;
/// `long sys_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg);`
pub const msgrcv: u64 = 188;
/// `long sys_msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg);`
pub const msgsnd: u64 = 189;
/// `long sys_semget(key_t key, int nsems, int semflg);`
pub const semget: u64 = 190;
/// `long sys_semctl(int semid, int semnum, int cmd, unsigned long arg);`
pub const semctl: u64 = 191;
/// `long sys_semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct __kernel_timespec __user *timeout);`
pub const semtimedop: u64 = 192;
/// `long sys_semop(int semid, struct sembuf __user *sops, unsigned nsops);`
pub const semop: u64 = 193;
/// `long sys_shmget(key_t key, size_t size, int flag);`
pub const shmget: u64 = 194;
/// `long sys_old_shmctl(int shmid, int cmd, struct shmid_ds __user *buf);`
pub const shmctl: u64 = 195;
/// `long sys_shmat(int shmid, char __user *shmaddr, int shmflg);`
pub const shmat: u64 = 196;
/// `long sys_shmdt(char __user *shmaddr);`
pub const shmdt: u64 = 197;
/// `long sys_socket(int, int, int);`
pub const socket: u64 = 198;
/// `long sys_socketpair(int, int, int, int __user *);`
pub const socketpair: u64 = 199;
/// `long sys_bind(int, struct sockaddr __user *, int);`
pub const bind: u64 = 200;
/// `long sys_listen(int, int);`
pub const listen: u64 = 201;
/// `long sys_accept(int, struct sockaddr __user *, int __user *);`
pub const accept: u64 = 202;
/// `long sys_connect(int, struct sockaddr __user *, int);`
pub const connect: u64 = 203;
/// `long sys_getsockname(int, struct sockaddr __user *, int __user *);`
pub const getsockname: u64 = 204;
/// `long sys_getpeername(int, struct sockaddr __user *, int __user *);`
pub const getpeername: u64 = 205;
/// `long sys_sendto(int, void __user *, size_t, unsigned, struct sockaddr __user *, int);`
pub const sendto: u64 = 206;
/// `long sys_recvfrom(int, void __user *, size_t, unsigned, struct sockaddr __user *, int __user *);`
pub const recvfrom: u64 = 207;
/// `long sys_setsockopt(int fd, int level, int optname, char __user *optval, int optlen);`
pub const setsockopt: u64 = 208;
/// `long sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen);`
pub const getsockopt: u64 = 209;
/// `long sys_shutdown(int, int);`
pub const shutdown: u64 = 210;
/// `long sys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags);`
pub const sendmsg: u64 = 211;
/// `long sys_recvmsg(int fd, struct user_msghdr __user *msg, unsigned flags);`
pub const recvmsg: u64 = 212;
/// `long sys_readahead(int fd, loff_t offset, size_t count);`
pub const readahead: u64 = 213;
/// `long sys_brk(unsigned long brk);`
pub const brk: u64 = 214;
/// `long sys_munmap(unsigned long addr, size_t len);`
pub const munmap: u64 = 215;
/// `long sys_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);`
pub const mremap: u64 = 216;
/// `long sys_add_key(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid);`
pub const add_key: u64 = 217;
/// `long sys_request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid);`
pub const request_key: u64 = 218;
/// `long sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);`
pub const keyctl: u64 = 219;
/// `long sys_clone(unsigned long, unsigned long, int __user *, unsigned long, int __user *);`
pub const clone: u64 = 220;
/// `long sys_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);`
pub const execve: u64 = 221;
/// `long sys_old_mmap(struct mmap_arg_struct __user *arg);`
pub const mmap: u64 = 222;
/// `long sys_fadvise64_64(int fd, loff_t offset, loff_t len, int advice);`
pub const fadvise64_64: u64 = 223;
/// `long sys_swapon(const char __user *specialfile, int swap_flags);`
pub const swapon: u64 = 224;
/// `long sys_swapoff(const char __user *specialfile);`
pub const swapoff: u64 = 225;
/// `long sys_mprotect(unsigned long start, size_t len, unsigned long prot);`
pub const mprotect: u64 = 226;
/// `long sys_msync(unsigned long start, size_t len, int flags);`
pub const msync: u64 = 227;
/// `long sys_mlock(unsigned long start, size_t len);`
pub const mlock: u64 = 228;
/// `long sys_munlock(unsigned long start, size_t len);`
pub const munlock: u64 = 229;
/// `long sys_mlockall(int flags);`
pub const mlockall: u64 = 230;
/// `long sys_munlockall(void);`
pub const munlockall: u64 = 231;
/// `long sys_mincore(unsigned long start, size_t len, unsigned char __user * vec);`
pub const mincore: u64 = 232;
/// `long sys_madvise(unsigned long start, size_t len, int behavior);`
pub const madvise: u64 = 233;
/// `long sys_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);`
pub const remap_file_pages: u64 = 234;
/// `long sys_mbind(unsigned long start, unsigned long len, unsigned long mode, const unsigned long __user *nmask, unsigned long maxnode, unsigned flags);`
pub const mbind: u64 = 235;
/// `long sys_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);`
pub const get_mempolicy: u64 = 236;
/// `long sys_set_mempolicy(int mode, const unsigned long __user *nmask, unsigned long maxnode);`
pub const set_mempolicy: u64 = 237;
/// `long sys_migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to);`
pub const migrate_pages: u64 = 238;
/// `long sys_move_pages(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags);`
pub const move_pages: u64 = 239;
/// `long sys_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig, siginfo_t __user *uinfo);`
pub const rt_tgsigqueueinfo: u64 = 240;
/// `long sys_perf_event_open(`
pub const perf_event_open: u64 = 241;
/// `long sys_accept4(int, struct sockaddr __user *, int __user *, int);`
pub const accept4: u64 = 242;
/// `long sys_recvmmsg_time32(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct old_timespec32 __user *timeout);`
pub const recvmmsg_time32: u64 = 243;
/// `long sys_wait4(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru);`
pub const wait4: u64 = 260;
/// `long sys_prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim);`
pub const prlimit64: u64 = 261;
/// `long sys_fanotify_init(unsigned int flags, unsigned int event_f_flags);`
pub const fanotify_init: u64 = 262;
/// `long sys_fanotify_mark(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char __user *pathname);`
pub const fanotify_mark: u64 = 263;
/// `long sys_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag);`
pub const name_to_handle_at: u64 = 264;
/// `long sys_open_by_handle_at(int mountdirfd, struct file_handle __user *handle, int flags);`
pub const open_by_handle_at: u64 = 265;
/// `long sys_clock_adjtime(clockid_t which_clock, struct __kernel_timex __user *tx);`
pub const clock_adjtime: u64 = 266;
/// `long sys_syncfs(int fd);`
pub const syncfs: u64 = 267;
/// `long sys_setns(int fd, int nstype);`
pub const setns: u64 = 268;
/// `long sys_sendmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags);`
pub const sendmmsg: u64 = 269;
/// `long sys_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);`
pub const process_vm_readv: u64 = 270;
/// `long sys_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);`
pub const process_vm_writev: u64 = 271;
/// `long sys_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);`
pub const kcmp: u64 = 272;
/// `long sys_finit_module(int fd, const char __user *uargs, int flags);`
pub const finit_module: u64 = 273;
/// `long sys_sched_setattr(pid_t pid, struct sched_attr __user *attr, unsigned int flags);`
pub const sched_setattr: u64 = 274;
/// `long sys_sched_getattr(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags);`
pub const sched_getattr: u64 = 275;
/// `long sys_renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);`
pub const renameat2: u64 = 276;
/// `long sys_seccomp(unsigned int op, unsigned int flags, void __user *uargs);`
pub const seccomp: u64 = 277;
/// `long sys_getrandom(char __user *buf, size_t count, unsigned int flags);`
pub const getrandom: u64 = 278;
/// `long sys_memfd_create(const char __user *uname_ptr, unsigned int flags);`
pub const memfd_create: u64 = 279;
/// `long sys_bpf(int cmd, union bpf_attr *attr, unsigned int size);`
pub const bpf: u64 = 280;
/// `long sys_execveat(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);`
pub const execveat: u64 = 281;
/// `long sys_userfaultfd(int flags);`
pub const userfaultfd: u64 = 282;
/// `long sys_membarrier(int cmd, unsigned int flags, int cpu_id);`
pub const membarrier: u64 = 283;
/// `long sys_mlock2(unsigned long start, size_t len, int flags);`
pub const mlock2: u64 = 284;
/// `long sys_copy_file_range(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);`
pub const copy_file_range: u64 = 285;
/// `long sys_preadv2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);`
pub const preadv2: u64 = 286;
/// `long sys_pwritev2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);`
pub const pwritev2: u64 = 287;
/// `long sys_pkey_mprotect(unsigned long start, size_t len, unsigned long prot, int pkey);`
pub const pkey_mprotect: u64 = 288;
/// `long sys_pkey_alloc(unsigned long flags, unsigned long init_val);`
pub const pkey_alloc: u64 = 289;
/// `long sys_pkey_free(int pkey);`
pub const pkey_free: u64 = 290;
/// `long sys_statx(int dfd, const char __user *path, unsigned flags, unsigned mask, struct statx __user *buffer);`
pub const statx: u64 = 291;
/// `long sys_io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout, const struct __aio_sigset *sig);`
pub const io_pgetevents: u64 = 292;
/// `long sys_rseq(struct rseq __user *rseq, uint32_t rseq_len, int flags, uint32_t sig);`
pub const rseq: u64 = 293;
/// `long sys_kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char __user *cmdline_ptr, unsigned long flags);`
pub const kexec_file_load: u64 = 294;
/// `long sys_pidfd_send_signal(int pidfd, int sig, siginfo_t __user *info, unsigned int flags);`
pub const pidfd_send_signal: u64 = 424;
/// `long sys_io_uring_setup(u32 entries, struct io_uring_params __user *p);`
pub const io_uring_setup: u64 = 425;
/// `long sys_io_uring_enter(unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const sigset_t __user *sig, size_t sigsz);`
pub const io_uring_enter: u64 = 426;
/// `long sys_io_uring_register(unsigned int fd, unsigned int op, void __user *arg, unsigned int nr_args);`
pub const io_uring_register: u64 = 427;
/// `long sys_open_tree(int dfd, const char __user *path, unsigned flags);`
pub const open_tree: u64 = 428;
/// `long sys_move_mount(int from_dfd, const char __user *from_path, int to_dfd, const char __user *to_path, unsigned int ms_flags);`
pub const move_mount: u64 = 429;
/// `long sys_fsopen(const char __user *fs_name, unsigned int flags);`
pub const fsopen: u64 = 430;
/// `long sys_fsconfig(int fs_fd, unsigned int cmd, const char __user *key, const void __user *value, int aux);`
pub const fsconfig: u64 = 431;
/// `long sys_fsmount(int fs_fd, unsigned int flags, unsigned int ms_flags);`
pub const fsmount: u64 = 432;
/// `long sys_fspick(int dfd, const char __user *path, unsigned int flags);`
pub const fspick: u64 = 433;
/// `long sys_pidfd_open(pid_t pid, unsigned int flags);`
pub const pidfd_open: u64 = 434;
/// `long sys_clone3(struct clone_args __user *uargs, size_t size);`
pub const clone3: u64 = 435;
/// `long sys_close_range(unsigned int fd, unsigned int max_fd, unsigned int flags);`
pub const close_range: u64 = 436;
/// `long sys_openat2(int dfd, const char __user *filename, struct open_how *how, size_t size);`
pub const openat2: u64 = 437;
/// `long sys_pidfd_getfd(int pidfd, int fd, unsigned int flags);`
pub const pidfd_getfd: u64 = 438;
/// `long sys_faccessat2(int dfd, const char __user *filename, int mode, int flags);`
pub const faccessat2: u64 = 439;
/// `long sys_process_madvise(int pidfd, const struct iovec __user *vec, size_t vlen, int behavior, unsigned int flags);`
pub const process_madvise: u64 = 440;
