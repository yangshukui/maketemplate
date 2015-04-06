
package main

/*

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <malloc.h>

#define INVALID_SYSCALL -1

#ifndef __NR_msgctl
#define __NR_msgctl INVALID_SYSCALL
#endif

#ifndef __NR_accept
#define __NR_accept INVALID_SYSCALL
#endif

#ifndef __NR_semctl
#define __NR_semctl INVALID_SYSCALL
#endif

#ifndef __NR_getsockname
#define __NR_getsockname INVALID_SYSCALL
#endif

#ifndef __NR_accept4
#define __NR_accept4 INVALID_SYSCALL
#endif

#ifndef __NR_listen
#define __NR_listen INVALID_SYSCALL
#endif

#ifndef __NR_semget
#define __NR_semget INVALID_SYSCALL
#endif

#ifndef __NR_epoll_wait_old
#define __NR_epoll_wait_old INVALID_SYSCALL
#endif

#ifndef __NR_recvmsg
#define __NR_recvmsg INVALID_SYSCALL
#endif

#ifndef __NR_recvfrom
#define __NR_recvfrom INVALID_SYSCALL
#endif

#ifndef __NR_socket
#define __NR_socket INVALID_SYSCALL
#endif

#ifndef __NR_semtimedop
#define __NR_semtimedop INVALID_SYSCALL
#endif

#ifndef __NR_msgrcv
#define __NR_msgrcv INVALID_SYSCALL
#endif

#ifndef __NR_getpeername
#define __NR_getpeername INVALID_SYSCALL
#endif

#ifndef __NR_msgsnd
#define __NR_msgsnd INVALID_SYSCALL
#endif

#ifndef __NR_sendmsg
#define __NR_sendmsg INVALID_SYSCALL
#endif

#ifndef __NR_shmdt
#define __NR_shmdt INVALID_SYSCALL
#endif

#ifndef __NR_connect
#define __NR_connect INVALID_SYSCALL
#endif

#ifndef __NR_msgget
#define __NR_msgget INVALID_SYSCALL
#endif

#ifndef __NR_tuxcall
#define __NR_tuxcall INVALID_SYSCALL
#endif

#ifndef __NR_getsockopt
#define __NR_getsockopt INVALID_SYSCALL
#endif

#ifndef __NR_socketpair
#define __NR_socketpair INVALID_SYSCALL
#endif

#ifndef __NR_newfstatat
#define __NR_newfstatat INVALID_SYSCALL
#endif

#ifndef __NR_sendto
#define __NR_sendto INVALID_SYSCALL
#endif

#ifndef __NR_semop
#define __NR_semop INVALID_SYSCALL
#endif

#ifndef __NR_setsockopt
#define __NR_setsockopt INVALID_SYSCALL
#endif

#ifndef __NR_bind
#define __NR_bind INVALID_SYSCALL
#endif

#ifndef __NR_shutdown
#define __NR_shutdown INVALID_SYSCALL
#endif

#ifndef __NR_arch_prctl
#define __NR_arch_prctl INVALID_SYSCALL
#endif

#ifndef __NR_shmat
#define __NR_shmat INVALID_SYSCALL
#endif

#ifndef __NR_shmctl
#define __NR_shmctl INVALID_SYSCALL
#endif

#ifndef __NR_epoll_ctl_old
#define __NR_epoll_ctl_old INVALID_SYSCALL
#endif

#ifndef __NR_shmget
#define __NR_shmget INVALID_SYSCALL
#endif

#ifndef __NR_security
#define __NR_security INVALID_SYSCALL
#endif

#ifndef __NR_arm_sync_file_range
#define __NR_arm_sync_file_range INVALID_SYSCALL
#endif

#ifndef __NR_kexec_file_load
#define __NR_kexec_file_load INVALID_SYSCALL
#endif

#ifndef __NR_syscall
#define __NR_syscall INVALID_SYSCALL
#endif

#ifndef __NR_sysmips
#define __NR_sysmips INVALID_SYSCALL
#endif

#ifndef __NR_cacheflush
#define __NR_cacheflush INVALID_SYSCALL
#endif

#ifndef __NR_oldwait4
#define __NR_oldwait4 INVALID_SYSCALL
#endif

#ifndef __NR_pciconfig_iobase
#define __NR_pciconfig_iobase INVALID_SYSCALL
#endif

#ifndef __NR_bpf
#define __NR_bpf INVALID_SYSCALL
#endif

#ifndef __NR_pciconfig_write
#define __NR_pciconfig_write INVALID_SYSCALL
#endif

#ifndef __NR_send
#define __NR_send INVALID_SYSCALL
#endif

#ifndef __NR_memfd_create
#define __NR_memfd_create INVALID_SYSCALL
#endif

#ifndef __NR_pciconfig_read
#define __NR_pciconfig_read INVALID_SYSCALL
#endif

#ifndef __NR_execveat
#define __NR_execveat INVALID_SYSCALL
#endif

#ifndef __NR_recv
#define __NR_recv INVALID_SYSCALL
#endif

#ifndef __NR_timerfd
#define __NR_timerfd INVALID_SYSCALL
#endif

#ifndef __NR_sync_file_range2
#define __NR_sync_file_range2 INVALID_SYSCALL
#endif

#ifndef __NR_cachectl
#define __NR_cachectl INVALID_SYSCALL
#endif

#ifndef __NR_arm_fadvise64_64
#define __NR_arm_fadvise64_64 INVALID_SYSCALL
#endif

#ifndef __NR_shmget
#define __NR_shmget INVALID_SYSCALL
#endif

#ifndef __NR_getrandom
#define __NR_getrandom INVALID_SYSCALL
#endif

struct scmp_map {
    int syscall;
    int action;
};

static int scmp_filter(struct scmp_map **syscall_filter, int num)
{
	struct sock_filter *sec_filter = malloc(sizeof(struct sock_filter) * (num * 2 + 3));
    if (sec_filter) {
		struct sock_filter scmp_head[] = {
	        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
	    };
	    memcpy(sec_filter, scmp_head, sizeof(scmp_head));
		
	    int i = 0;
		int fil_index = 0;
	    for ( ; i < num; i++)
	    {
		    if (INVALID_SYSCALL == (*syscall_filter)[i].syscall) {
				continue;
			}
			
	        struct sock_filter node[] = {
	            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (*syscall_filter)[i].syscall, 0, 1),
	            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
	        };
	        memcpy(&sec_filter[1 + fil_index * 2], node, sizeof(node));
			fil_index++;
	    }
	    struct sock_filter scmp_end[] = {
	        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP),
	        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
	    };
	    memcpy(&sec_filter[1 + fil_index * 2], scmp_end, sizeof(scmp_end));
	    
	    struct sock_fprog prog = {
	        .len = (unsigned short)(fil_index * 2 + 3),
	        .filter = sec_filter,
	    };
	    
	    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
			|| prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		    perror("prctl error");
			free(sec_filter);
		    return 1;
		}
	    free(sec_filter);
    }
    return 0;
}
*/
import "C"

import (
	"errors"
	"unsafe"
	"syscall"
	"fmt"
	"os/exec"
)

type Action struct {
	syscall int
	action  int
	args    string
}

type ScmpCtx struct {
	CallMap map[string]Action
}

var SyscallMap = map[string]int{
	"restart_syscall":              C.__NR_restart_syscall,
	"exit":                         C.__NR_exit,
	"fork":                         C.__NR_fork,
	"read":                         C.__NR_read,
	"write":                        C.__NR_write,
	"open":                         C.__NR_open,
	"close":                        C.__NR_close,
	"waitpid":                      C.__NR_waitpid,
	"creat":                        C.__NR_creat,
	"link":                         C.__NR_link,
	"unlink":                       C.__NR_unlink,
	"execve":                       C.__NR_execve,
	"chdir":                        C.__NR_chdir,
	"time":                         C.__NR_time,
	"mknod":                        C.__NR_mknod,
	"chmod":                        C.__NR_chmod,
	"lchown":                       C.__NR_lchown,
	"break":                        C.__NR_break,
	"oldstat":                      C.__NR_oldstat,
	"lseek":                        C.__NR_lseek,
	"getpid":                       C.__NR_getpid,
	"mount":                        C.__NR_mount,
	"umount":                       C.__NR_umount,
	"setuid":                       C.__NR_setuid,
	"getuid":                       C.__NR_getuid,
	"stime":                        C.__NR_stime,
	"ptrace":                       C.__NR_ptrace,
	"alarm":                        C.__NR_alarm,
	"oldfstat":                     C.__NR_oldfstat,
	"pause":                        C.__NR_pause,
	"utime":                        C.__NR_utime,
	"stty":                         C.__NR_stty,
	"gtty":                         C.__NR_gtty,
	"access":                       C.__NR_access,
	"nice":                         C.__NR_nice,
	"ftime":                        C.__NR_ftime,
	"sync":                         C.__NR_sync,
	"kill":                         C.__NR_kill,
	"rename":                       C.__NR_rename,
	"mkdir":                        C.__NR_mkdir,
	"rmdir":                        C.__NR_rmdir,
	"dup":                          C.__NR_dup,
	"pipe":                         C.__NR_pipe,
	"times":                        C.__NR_times,
	"prof":                         C.__NR_prof,
	"brk":                          C.__NR_brk,
	"setgid":                       C.__NR_setgid,
	"getgid":                       C.__NR_getgid,
	"signal":                       C.__NR_signal,
	"geteuid":                      C.__NR_geteuid,
	"getegid":                      C.__NR_getegid,
	"acct":                         C.__NR_acct,
	"umount2":                      C.__NR_umount2,
	"lock":                         C.__NR_lock,
	"ioctl":                        C.__NR_ioctl,
	"fcntl":                        C.__NR_fcntl,
	"mpx":                          C.__NR_mpx,
	"setpgid":                      C.__NR_setpgid,
	"ulimit":                       C.__NR_ulimit,
	"oldolduname":                  C.__NR_oldolduname,
	"umask":                        C.__NR_umask,
	"chroot":                       C.__NR_chroot,
	"ustat":                        C.__NR_ustat,
	"dup2":                         C.__NR_dup2,
	"getppid":                      C.__NR_getppid,
	"getpgrp":                      C.__NR_getpgrp,
	"setsid":                       C.__NR_setsid,
	"sigaction":                    C.__NR_sigaction,
	"sgetmask":                     C.__NR_sgetmask,
	"ssetmask":                     C.__NR_ssetmask,
	"setreuid":                     C.__NR_setreuid,
	"setregid":                     C.__NR_setregid,
	"sigsuspend":                   C.__NR_sigsuspend,
	"sigpending":                   C.__NR_sigpending,
	"sethostname":                  C.__NR_sethostname,
	"setrlimit":                    C.__NR_setrlimit,
	"getrlimit":                    C.__NR_getrlimit,
	"getrusage":                    C.__NR_getrusage,
	"gettimeofday":                 C.__NR_gettimeofday,
	"settimeofday":                 C.__NR_settimeofday,
	"getgroups":                    C.__NR_getgroups,
	"setgroups":                    C.__NR_setgroups,
	"select":                       C.__NR_select,
	"symlink":                      C.__NR_symlink,
	"oldlstat":                     C.__NR_oldlstat,
	"readlink":                     C.__NR_readlink,
	"uselib":                       C.__NR_uselib,
	"swapon":                       C.__NR_swapon,
	"reboot":                       C.__NR_reboot,
	"readdir":                      C.__NR_readdir,
	"mmap":                         C.__NR_mmap,
	"munmap":                       C.__NR_munmap,
	"truncate":                     C.__NR_truncate,
	"ftruncate":                    C.__NR_ftruncate,
	"fchmod":                       C.__NR_fchmod,
	"fchown":                       C.__NR_fchown,
	"getpriority":                  C.__NR_getpriority,
	"setpriority":                  C.__NR_setpriority,
	"profil":                       C.__NR_profil,
	"statfs":                       C.__NR_statfs,
	"fstatfs":                      C.__NR_fstatfs,
	"ioperm":                       C.__NR_ioperm,
	"socketcall":                   C.__NR_socketcall,
	"syslog":                       C.__NR_syslog,
	"setitimer":                    C.__NR_setitimer,
	"getitimer":                    C.__NR_getitimer,
	"stat":                         C.__NR_stat,
	"lstat":                        C.__NR_lstat,
	"fstat":                        C.__NR_fstat,
	"olduname":                     C.__NR_olduname,
	"iopl":                         C.__NR_iopl,
	"vhangup":                      C.__NR_vhangup,
	"idle":                         C.__NR_idle,
	"vm86old":                      C.__NR_vm86old,
	"wait4":                        C.__NR_wait4,
	"swapoff":                      C.__NR_swapoff,
	"sysinfo":                      C.__NR_sysinfo,
	"ipc":                          C.__NR_ipc,
	"fsync":                        C.__NR_fsync,
	"sigreturn":                    C.__NR_sigreturn,
	"clone":                        C.__NR_clone,
	"setdomainname":                C.__NR_setdomainname,
	"uname":                        C.__NR_uname,
	"modify_ldt":                   C.__NR_modify_ldt,
	"adjtimex":                     C.__NR_adjtimex,
	"mprotect":                     C.__NR_mprotect,
	"sigprocmask":                  C.__NR_sigprocmask,
	"create_module":                C.__NR_create_module,
	"init_module":                  C.__NR_init_module,
	"delete_module":                C.__NR_delete_module,
	"get_kernel_syms":              C.__NR_get_kernel_syms,
	"quotactl":                     C.__NR_quotactl,
	"getpgid":                      C.__NR_getpgid,
	"fchdir":                       C.__NR_fchdir,
	"bdflush":                      C.__NR_bdflush,
	"sysfs":                        C.__NR_sysfs,
	"personality":                  C.__NR_personality,
	"afs_syscall":                  C.__NR_afs_syscall,
	"setfsuid":                     C.__NR_setfsuid,
	"setfsgid":                     C.__NR_setfsgid,
	"_llseek":                      C.__NR__llseek,
	"getdents":                     C.__NR_getdents,
	"_newselect":                   C.__NR__newselect,
	"flock":                        C.__NR_flock,
	"msync":                        C.__NR_msync,
	"readv":                        C.__NR_readv,
	"writev":                       C.__NR_writev,
	"getsid":                       C.__NR_getsid,
	"fdatasync":                    C.__NR_fdatasync,
	"_sysctl":                      C.__NR__sysctl,
	"mlock":                        C.__NR_mlock,
	"munlock":                      C.__NR_munlock,
	"mlockall":                     C.__NR_mlockall,
	"munlockall":                   C.__NR_munlockall,
	"sched_setparam":               C.__NR_sched_setparam,
	"sched_getparam":               C.__NR_sched_getparam,
	"sched_setscheduler":           C.__NR_sched_setscheduler,
	"sched_getscheduler":           C.__NR_sched_getscheduler,
	"sched_yield":                  C.__NR_sched_yield,
	"sched_get_priority_max":       C.__NR_sched_get_priority_max,
	"sched_get_priority_min":       C.__NR_sched_get_priority_min,
	"sched_rr_get_interval":        C.__NR_sched_rr_get_interval,
	"nanosleep":                    C.__NR_nanosleep,
	"mremap":                       C.__NR_mremap,
	"setresuid":                    C.__NR_setresuid,
	"getresuid":                    C.__NR_getresuid,
	"vm86":                         C.__NR_vm86,
	"query_module":                 C.__NR_query_module,
	"poll":                         C.__NR_poll,
	"nfsservctl":                   C.__NR_nfsservctl,
	"setresgid":                    C.__NR_setresgid,
	"getresgid":                    C.__NR_getresgid,
	"prctl":                        C.__NR_prctl,
	"rt_sigreturn":                 C.__NR_rt_sigreturn,
	"rt_sigaction":                 C.__NR_rt_sigaction,
	"rt_sigprocmask":               C.__NR_rt_sigprocmask,
	"rt_sigpending":                C.__NR_rt_sigpending,
	"rt_sigtimedwait":              C.__NR_rt_sigtimedwait,
	"rt_sigqueueinfo":              C.__NR_rt_sigqueueinfo,
	"rt_sigsuspend":                C.__NR_rt_sigsuspend,
	"pread64":                      C.__NR_pread64,
	"pwrite64":                     C.__NR_pwrite64,
	"chown":                        C.__NR_chown,
	"getcwd":                       C.__NR_getcwd,
	"capget":                       C.__NR_capget,
	"capset":                       C.__NR_capset,
	"sigaltstack":                  C.__NR_sigaltstack,
	"sendfile":                     C.__NR_sendfile,
	"getpmsg":                      C.__NR_getpmsg,
	"putpmsg":                      C.__NR_putpmsg,
	"vfork":                        C.__NR_vfork,
	"ugetrlimit":                   C.__NR_ugetrlimit,
	"mmap2":                        C.__NR_mmap2,
	"truncate64":                   C.__NR_truncate64,
	"ftruncate64":                  C.__NR_ftruncate64,
	"stat64":                       C.__NR_stat64,
	"lstat64":                      C.__NR_lstat64,
	"fstat64":                      C.__NR_fstat64,
	"lchown32":                     C.__NR_lchown32,
	"getuid32":                     C.__NR_getuid32,
	"getgid32":                     C.__NR_getgid32,
	"geteuid32":                    C.__NR_geteuid32,
	"getegid32":                    C.__NR_getegid32,
	"setreuid32":                   C.__NR_setreuid32,
	"setregid32":                   C.__NR_setregid32,
	"getgroups32":                  C.__NR_getgroups32,
	"setgroups32":                  C.__NR_setgroups32,
	"fchown32":                     C.__NR_fchown32,
	"setresuid32":                  C.__NR_setresuid32,
	"getresuid32":                  C.__NR_getresuid32,
	"setresgid32":                  C.__NR_setresgid32,
	"getresgid32":                  C.__NR_getresgid32,
	"chown32":                      C.__NR_chown32,
	"setuid32":                     C.__NR_setuid32,
	"setgid32":                     C.__NR_setgid32,
	"setfsuid32":                   C.__NR_setfsuid32,
	"setfsgid32":                   C.__NR_setfsgid32,
	"pivot_root":                   C.__NR_pivot_root,
	"mincore":                      C.__NR_mincore,
	"madvise":                      C.__NR_madvise,
	"getdents64":                   C.__NR_getdents64,
	"fcntl64":                      C.__NR_fcntl64,
	"gettid":                       C.__NR_gettid,
	"readahead":                    C.__NR_readahead,
	"setxattr":                     C.__NR_setxattr,
	"lsetxattr":                    C.__NR_lsetxattr,
	"fsetxattr":                    C.__NR_fsetxattr,
	"getxattr":                     C.__NR_getxattr,
	"lgetxattr":                    C.__NR_lgetxattr,
	"fgetxattr":                    C.__NR_fgetxattr,
	"listxattr":                    C.__NR_listxattr,
	"llistxattr":                   C.__NR_llistxattr,
	"flistxattr":                   C.__NR_flistxattr,
	"removexattr":                  C.__NR_removexattr,
	"lremovexattr":                 C.__NR_lremovexattr,
	"fremovexattr":                 C.__NR_fremovexattr,
	"tkill":                        C.__NR_tkill,
	"sendfile64":                   C.__NR_sendfile64,
	"futex":                        C.__NR_futex,
	"sched_setaffinity":            C.__NR_sched_setaffinity,
	"sched_getaffinity":            C.__NR_sched_getaffinity,
	"set_thread_area":              C.__NR_set_thread_area,
	"get_thread_area":              C.__NR_get_thread_area,
	"io_setup":                     C.__NR_io_setup,
	"io_destroy":                   C.__NR_io_destroy,
	"io_getevents":                 C.__NR_io_getevents,
	"io_submit":                    C.__NR_io_submit,
	"io_cancel":                    C.__NR_io_cancel,
	"fadvise64":                    C.__NR_fadvise64,
	"exit_group":                   C.__NR_exit_group,
	"lookup_dcookie":               C.__NR_lookup_dcookie,
	"epoll_create":                 C.__NR_epoll_create,
	"epoll_ctl":                    C.__NR_epoll_ctl,
	"epoll_wait":                   C.__NR_epoll_wait,
	"remap_file_pages":             C.__NR_remap_file_pages,
	"set_tid_address":              C.__NR_set_tid_address,
	"timer_create":                 C.__NR_timer_create,
	"timer_settime":                C.__NR_timer_settime,
	"timer_gettime":                C.__NR_timer_gettime,
	"timer_getoverrun":             C.__NR_timer_getoverrun,
	"timer_delete":                 C.__NR_timer_delete,
	"clock_settime":                C.__NR_clock_settime,
	"clock_gettime":                C.__NR_clock_gettime,
	"clock_getres":                 C.__NR_clock_getres,
	"clock_nanosleep":              C.__NR_clock_nanosleep,
	"statfs64":                     C.__NR_statfs64,
	"fstatfs64":                    C.__NR_fstatfs64,
	"tgkill":                       C.__NR_tgkill,
	"utimes":                       C.__NR_utimes,
	"fadvise64_64":                 C.__NR_fadvise64_64,
	"vserver":                      C.__NR_vserver,
	"mbind":                        C.__NR_mbind,
	"get_mempolicy":                C.__NR_get_mempolicy,
	"set_mempolicy":                C.__NR_set_mempolicy,
	"mq_open":                      C.__NR_mq_open,
	"mq_unlink":                    C.__NR_mq_unlink,
	"mq_timedsend":                 C.__NR_mq_timedsend,
	"mq_timedreceive":              C.__NR_mq_timedreceive,
	"mq_notify":                    C.__NR_mq_notify,
	"mq_getsetattr":                C.__NR_mq_getsetattr,
	"kexec_load":                   C.__NR_kexec_load,
	"waitid":                       C.__NR_waitid,
	"add_key":                      C.__NR_add_key,
	"request_key":                  C.__NR_request_key,
	"keyctl":                       C.__NR_keyctl,
	"ioprio_set":                   C.__NR_ioprio_set,
	"ioprio_get":                   C.__NR_ioprio_get,
	"inotify_init":                 C.__NR_inotify_init,
	"inotify_add_watch":            C.__NR_inotify_add_watch,
	"inotify_rm_watch":             C.__NR_inotify_rm_watch,
	"migrate_pages":                C.__NR_migrate_pages,
	"openat":                       C.__NR_openat,
	"mkdirat":                      C.__NR_mkdirat,
	"mknodat":                      C.__NR_mknodat,
	"fchownat":                     C.__NR_fchownat,
	"futimesat":                    C.__NR_futimesat,
	"fstatat64":                    C.__NR_fstatat64,
	"unlinkat":                     C.__NR_unlinkat,
	"renameat":                     C.__NR_renameat,
	"linkat":                       C.__NR_linkat,
	"symlinkat":                    C.__NR_symlinkat,
	"readlinkat":                   C.__NR_readlinkat,
	"fchmodat":                     C.__NR_fchmodat,
	"faccessat":                    C.__NR_faccessat,
	"pselect6":                     C.__NR_pselect6,
	"ppoll":                        C.__NR_ppoll,
	"unshare":                      C.__NR_unshare,
	"set_robust_list":              C.__NR_set_robust_list,
	"get_robust_list":              C.__NR_get_robust_list,
	"splice":                       C.__NR_splice,
	"sync_file_range":              C.__NR_sync_file_range,
	"tee":                          C.__NR_tee,
	"vmsplice":                     C.__NR_vmsplice,
	"move_pages":                   C.__NR_move_pages,
	"getcpu":                       C.__NR_getcpu,
	"epoll_pwait":                  C.__NR_epoll_pwait,
	"utimensat":                    C.__NR_utimensat,
	"signalfd":                     C.__NR_signalfd,
	"timerfd_create":               C.__NR_timerfd_create,
	"eventfd":                      C.__NR_eventfd,
	"fallocate":                    C.__NR_fallocate,
	"timerfd_settime":              C.__NR_timerfd_settime,
	"timerfd_gettime":              C.__NR_timerfd_gettime,
	"signalfd4":                    C.__NR_signalfd4,
	"eventfd2":                     C.__NR_eventfd2,
	"epoll_create1":                C.__NR_epoll_create1,
	"dup3":                         C.__NR_dup3,
	"pipe2":                        C.__NR_pipe2,
	"inotify_init1":                C.__NR_inotify_init1,
	"preadv":                       C.__NR_preadv,
	"pwritev":                      C.__NR_pwritev,
	"rt_tgsigqueueinfo":            C.__NR_rt_tgsigqueueinfo,
	"perf_event_open":              C.__NR_perf_event_open,
	"recvmmsg":                     C.__NR_recvmmsg,
	"fanotify_init":                C.__NR_fanotify_init,
	"fanotify_mark":                C.__NR_fanotify_mark,
	"prlimit64":                    C.__NR_prlimit64,
	"name_to_handle_at":            C.__NR_name_to_handle_at,
	"open_by_handle_at":            C.__NR_open_by_handle_at,
	"clock_adjtime":                C.__NR_clock_adjtime,
	"syncfs":                       C.__NR_syncfs,
	"sendmmsg":                     C.__NR_sendmmsg,
	"setns":                        C.__NR_setns,
	"process_vm_readv":             C.__NR_process_vm_readv,
	"process_vm_writev":            C.__NR_process_vm_writev,
	"kcmp":                         C.__NR_kcmp,
	"finit_module":                 C.__NR_finit_module,
	"sched_setattr":                C.__NR_sched_setattr,
	"sched_getattr":                C.__NR_sched_getattr,
	"renameat2":                    C.__NR_renameat2,
	"seccomp":                      C.__NR_seccomp,
}

var SyscallMapMin = map[string]int{	
	"read":                         C.__NR_read,
	"write":                        C.__NR_write,
	"open":                         C.__NR_open,
	"close":                        C.__NR_close,	
	"execve":                       C.__NR_execve,
	"access":                       C.__NR_access,
	"brk":                          C.__NR_brk,
	"sigaction":                    C.__NR_sigaction,
	"munmap":                       C.__NR_munmap,
	"fstat":                        C.__NR_fstat,
	"sigreturn":                    C.__NR_sigreturn,
	"clone":                        C.__NR_clone,
	"mprotect":                     C.__NR_mprotect,
	"sigprocmask":                  C.__NR_sigprocmask,
	"getpgid":                      C.__NR_getpgid,
	"rt_sigreturn":                 C.__NR_rt_sigreturn,
	"rt_sigaction":                 C.__NR_rt_sigaction,
	"rt_sigprocmask":               C.__NR_rt_sigprocmask,
	"mmap2":                        C.__NR_mmap2,
	"stat64":                       C.__NR_stat64,
	"fstat64":                      C.__NR_fstat64,
	"futex":                        C.__NR_futex,
	"set_thread_area":              C.__NR_set_thread_area,
	"exit_group":                   C.__NR_exit_group,
	"clock_gettime":                C.__NR_clock_gettime,
	"statfs64":                     C.__NR_statfs64,
	"pipe2":                        C.__NR_pipe2,
	"fstatfs64":                    C.__NR_fstatfs64,
}

var scmpActAllow = 0

func ScmpInit(action int) (*ScmpCtx, error) {
	ctx := ScmpCtx{CallMap: make(map[string]Action)}
	return &ctx, nil
}

func ScmpAdd(ctx *ScmpCtx, call string, action int) error {
	_, exists := ctx.CallMap[call]
	if exists {
		return errors.New("syscall exist")
	}
	sysCall, sysExists := SyscallMap[call]
	if sysExists {
		ctx.CallMap[call] = Action{sysCall, action, ""}
	}

	return errors.New("syscall not surport")
}

func ScmpDel(ctx *ScmpCtx, call string) error {
	_, exists := ctx.CallMap[call]
	if exists {
		delete(ctx.CallMap, call)
		return nil
	}

	return errors.New("syscall not exist")
}

func ScmpLoad(ctx *ScmpCtx) error {
	for key := range SyscallMapMin {
		ScmpAdd(ctx, key, scmpActAllow)
	}

	num := len(ctx.CallMap)
	filter := make([]C.struct_scmp_map, num)

	index := 0
	for _, value := range ctx.CallMap {
		filter[index].syscall = C.int(value.syscall)
		filter[index].action = C.int(value.action)
		index++
	}

	res := C.scmp_filter((**C.struct_scmp_map)(unsafe.Pointer(&filter)), C.int(num))
	if 0 != res {
		return errors.New("SeccompLoad error")
	}
	return nil
}

/*
func finalizeSeccomp(config *initConfig) error {
	scmpCtx, _ := ScmpInit(scmpActAllow)

	for _, call := range config.Config.SysCalls {
		ScmpAdd(scmpCtx, call, scmpActAllow)
	}

	return ScmpLoad(scmpCtx)
}
*/

func  main(){
	scmpCtx, _ := ScmpInit(scmpActAllow)
	//for key := range SyscallMap {
	//    if key != "chmod" {
	//	    ScmpAdd(scmpCtx, key, scmpActAllow)
	//	}
	//}
	//ScmpAdd(scmpCtx, "mknod", scmpActAllow)
	
	ScmpLoad(scmpCtx)
	
	fmt.Printf("printf ---- \n");
	
	syscall.Chmod("bpf-direct.c", 0777)
	//fmt.Printf("getpid [%d]\n", syscall.Getpid())
	
	argv := []string{"./sda", "b", "8", "0"}
    c := exec.Command("mknod", argv...)
    d, _ := c.Output()
    fmt.Println(string(d))
	fmt.Printf("printf ---- \n");
}

/*
var SyscallMapMin = map[string]int{	
	"write":                        C.__NR_write,
	"rt_sigreturn":                 C.__NR_rt_sigreturn,
	"exit_group":                   C.__NR_exit_group,
	"futex":                        C.__NR_futex,
}
*/

/*
var SyscallMapMin = map[string]int{	
	"read":                         C.__NR_read,
	"write":                        C.__NR_write,
	"open":                         C.__NR_open,
	"close":                        C.__NR_close,	
	"execve":                       C.__NR_execve,
	"access":                       C.__NR_access,
	"brk":                          C.__NR_brk,
	"sigaction":                    C.__NR_sigaction,
	"munmap":                       C.__NR_munmap,
	"fstat":                        C.__NR_fstat,
	"sigreturn":                    C.__NR_sigreturn,
	"clone":                        C.__NR_clone,
	"mprotect":                     C.__NR_mprotect,
	"sigprocmask":                  C.__NR_sigprocmask,
	"getpgid":                      C.__NR_getpgid,
	"rt_sigreturn":                 C.__NR_rt_sigreturn,
	"rt_sigaction":                 C.__NR_rt_sigaction,
	"rt_sigprocmask":               C.__NR_rt_sigprocmask,
	"mmap2":                        C.__NR_mmap2,
	"stat64":                       C.__NR_stat64,
	"fstat64":                      C.__NR_fstat64,
	"futex":                        C.__NR_futex,
	"set_thread_area":              C.__NR_set_thread_area,
	"exit_group":                   C.__NR_exit_group,
	"clock_gettime":                C.__NR_clock_gettime,
	"statfs64":                     C.__NR_statfs64,
	"pipe2":                        C.__NR_pipe2,
	"fstatfs64":                    C.__NR_fstatfs64,
	"wait4":                        C.__NR_wait4,
}
*/
