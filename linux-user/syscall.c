/*
 *  Linux syscalls
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#define _ATFILE_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <elf.h>
#include <endian.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/swap.h>
#include <linux/capability.h>
#include <signal.h>
#include <sched.h>
#ifdef __ia64__
int __clone2(int (*fn)(void *), void *child_stack_base,
             size_t stack_size, int flags, void *arg, ...);
#endif
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/times.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/statfs.h>
#include <utime.h>
#include <sys/sysinfo.h>
//#include <sys/user.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/wireless.h>
#include <linux/icmp.h>
#include "qemu-common.h"
#ifdef CONFIG_TIMERFD
#include <sys/timerfd.h>
#endif
#ifdef TARGET_GPROF
#include <sys/gmon.h>
#endif
#ifdef CONFIG_EVENTFD
#include <sys/eventfd.h>
#endif
#ifdef CONFIG_EPOLL
#include <sys/epoll.h>
#endif
#ifdef CONFIG_ATTR
#include "qemu/xattr.h"
#endif
#ifdef CONFIG_SENDFILE
#include <sys/sendfile.h>
#endif

#define termios host_termios
#define winsize host_winsize
#define termio host_termio
#define sgttyb host_sgttyb /* same as target */
#define tchars host_tchars /* same as target */
#define ltchars host_ltchars /* same as target */

#include <linux/termios.h>
#include <linux/unistd.h>
#include <linux/cdrom.h>
#include <linux/hdreg.h>
#include <linux/soundcard.h>
#include <linux/kd.h>
#include <linux/mtio.h>
#include <linux/fs.h>
#if defined(CONFIG_FIEMAP)
#include <linux/fiemap.h>
#endif
#include <linux/fb.h>
#include <linux/vt.h>
#include <linux/dm-ioctl.h>
#include <linux/reboot.h>
#include <linux/route.h>
#include <linux/filter.h>
#include <linux/blkpg.h>
#include "linux_loop.h"
#include "uname.h"

#include "qemu.h"

//#define DEBUG


#undef _syscall0
#undef _syscall1
#undef _syscall2
#undef _syscall3
#undef _syscall4
#undef _syscall5
#undef _syscall6

#define _syscall0(type,name)		\
static type name (void)			\
{					\
	return syscall(__NR_##name);	\
}

#define _syscall1(type,name,type1,arg1)		\
static type name (type1 arg1)			\
{						\
	return syscall(__NR_##name, arg1);	\
}

#define _syscall2(type,name,type1,arg1,type2,arg2)	\
static type name (type1 arg1,type2 arg2)		\
{							\
	return syscall(__NR_##name, arg1, arg2);	\
}

#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3)	\
static type name (type1 arg1,type2 arg2,type3 arg3)		\
{								\
	return syscall(__NR_##name, arg1, arg2, arg3);		\
}

#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4)	\
static type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4)			\
{										\
	return syscall(__NR_##name, arg1, arg2, arg3, arg4);			\
}

#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,	\
		  type5,arg5)							\
static type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5)	\
{										\
	return syscall(__NR_##name, arg1, arg2, arg3, arg4, arg5);		\
}


#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,	\
		  type5,arg5,type6,arg6)					\
static type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,	\
                  type6 arg6)							\
{										\
	return syscall(__NR_##name, arg1, arg2, arg3, arg4, arg5, arg6);	\
}


#ifdef __NR_exit_group
_syscall1(int,exit_group,int,error_code)
#endif


/* CGC TODO: which select? */
#if defined(TARGET_NR_pselect6)
#ifndef __NR_pselect6
# define __NR_pselect6 -1
#endif
#define __NR_sys_pselect6 __NR_pselect6
_syscall6(int, sys_pselect6, int, nfds, fd_set *, readfds, fd_set *, writefds,
          fd_set *, exceptfds, struct timespec *, timeout, void *, sig);
#endif

unsigned first_recv = 1;
unsigned do_eof_exit;
unsigned zero_recv_hits = 0;

static inline int host_to_target_errno(int err)
{
    /* From binfmt_cgc.c cgc_map_err */
    switch (err) {
    case EBADF:
        return TARGET_EBADF;
    case EFAULT:
        return TARGET_EFAULT;
    case EINVAL:
        return TARGET_EINVAL;
    case ENOMEM:
        return TARGET_ENOMEM;
    case ENOSYS:
        return TARGET_ENOSYS;
    case EPIPE:
        return TARGET_EPIPE;
    case EINTR:
    /* CGC TODO: binfmt_cgc also includes these - they can't reach userspace, right?
    case ERESTARTSYS:
    case ERESTARTNOINTR:
    case ERESTARTNOHAND:
    case ERESTART_RESTARTBLOCK:
    */
        /* CGC auto-restarts syscalls, these must never occurr */
        fprintf(stderr, "qemu: INTERNAL ERROR: A syscall returned EINTR: this cannot happen in CGC, we would need to automatically restart it.");
        exit(-36);
    }
    return TARGET_EINVAL;
}

static inline int target_to_host_errno(int err)
{
    switch (err) {
    case TARGET_EBADF:
        return EBADF;
    case TARGET_EFAULT:
        return EFAULT;
    case TARGET_EINVAL:
        return EINVAL;
    case TARGET_ENOMEM:
        return ENOMEM;
    case TARGET_ENOSYS:
        return ENOSYS;
    case TARGET_EPIPE:
        return EPIPE;
    }
    assert(false);
    return EBADSLT; /* Meaningless value */
}

static inline abi_long get_errno(abi_long ret)
{
    if (ret == -1)
        return host_to_target_errno(errno); /* Note: CGC error returns are >0 */
    else
        return ret;
}

static inline int is_error(abi_long ret)
{
    return (abi_ulong)ret >= (abi_ulong)(-4096);
}

char *target_strerror(int err)
{
    if ((err >= 4000) || (err < 0)) {
        return NULL; /* Can this actually happen? */
    }
    return strerror(target_to_host_errno(err));
}


static inline abi_long copy_from_user_fdset(fd_set *fds,
                                            abi_ulong target_fds_addr,
                                            int n)
{
    int i, nw, j, k;
    abi_ulong b, *target_fds;

    nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
    if (!(target_fds = lock_user(VERIFY_READ,
                                 target_fds_addr,
                                 sizeof(abi_ulong) * nw,
                                 1)))
        return TARGET_EFAULT;

    FD_ZERO(fds);
    k = 0;
    for (i = 0; i < nw; i++) {
        /* grab the abi_ulong */
        __get_user(b, &target_fds[i]);
        for (j = 0; j < TARGET_ABI_BITS; j++) {
            /* check the bit inside the abi_ulong */
            if ((b >> j) & 1)
                FD_SET(k, fds);
            k++;
        }
    }

    unlock_user(target_fds, target_fds_addr, 0);

    return 0;
}

static inline abi_ulong copy_from_user_fdset_ptr(fd_set *fds, fd_set **fds_ptr,
                                                 abi_ulong target_fds_addr,
                                                 int n)
{
    if (target_fds_addr) {
        if (copy_from_user_fdset(fds, target_fds_addr, n))
            return TARGET_EFAULT;
        *fds_ptr = fds;
    } else {
        *fds_ptr = NULL;
    }
    return 0;
}

static inline abi_long copy_to_user_fdset(abi_ulong target_fds_addr,
                                          const fd_set *fds,
                                          int n)
{
    int i, nw, j, k;
    abi_long v;
    abi_ulong *target_fds;

    nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
    if (!(target_fds = lock_user(VERIFY_WRITE,
                                 target_fds_addr,
                                 sizeof(abi_ulong) * nw,
                                 0)))
        return TARGET_EFAULT;

    k = 0;
    for (i = 0; i < nw; i++) {
        v = 0;
        for (j = 0; j < TARGET_ABI_BITS; j++) {
            v |= ((abi_ulong)(FD_ISSET(k, fds) != 0) << j);
            k++;
        }
        __put_user(v, &target_fds[i]);
    }

    unlock_user(target_fds, target_fds_addr, sizeof(abi_ulong) * nw);

    return 0;
}

static inline abi_long copy_from_user_timeval(struct timeval *tv,
        abi_ulong target_tv_addr)
{
    struct target_timeval *target_tv;

    if (!lock_user_struct(VERIFY_READ, target_tv, target_tv_addr, 1))
        return TARGET_EFAULT;

    __get_user(tv->tv_sec, &target_tv->tv_sec);
    __get_user(tv->tv_usec, &target_tv->tv_usec);

    unlock_user_struct(target_tv, target_tv_addr, 0);

    return 0;
}

static inline abi_long copy_to_user_timeval(abi_ulong target_tv_addr,
        const struct timeval *tv)
{
    struct target_timeval *target_tv;

    if (!lock_user_struct(VERIFY_WRITE, target_tv, target_tv_addr, 0))
        return TARGET_EFAULT;

    __put_user(tv->tv_sec, &target_tv->tv_sec);
    __put_user(tv->tv_usec, &target_tv->tv_usec);

    unlock_user_struct(target_tv, target_tv_addr, 1);

    return 0;
}



void syscall_init(void)
{
}


/* Map host to target signal numbers for the wait family of syscalls.
   Assume all other status bits are the same.  */
int host_to_target_waitstatus(int status)
{
    if (WIFSIGNALED(status)) {
        return host_to_target_signal(WTERMSIG(status)) | (status & ~0x7f);
    }
    if (WIFSTOPPED(status)) {
        return (host_to_target_signal(WSTOPSIG(status)) << 8)
               | (status & 0xff);
    }
    return status;
}



_Static_assert(sizeof(abi_long) == 4, "abi_long is not 4 bytes!");
_Static_assert(sizeof(abi_int) == 4, "abi_int is not 4 bytes!");


/* The functions are approximate copies of the kernel code */
/* Note: usually even qemu's original code does not call unlock_user on errors.
 *       (And unless DEBUG_REMAP is defined it's a no-op anyway.) */

static abi_long do_receive(CPUX86State *env, abi_long fd, abi_ulong buf, abi_long count, abi_ulong p_rx_bytes) {
    /* start the forkserver on the first call to receive to save even more time */
    if (first_recv)
    {
        afl_setup();
        afl_forkserver(env);
        first_recv = 0;
    }

    int ret = 0;
    abi_ulong *p; abi_long *prx;

    /* adjust receive to use stdin if it requests stdout */
    if (fd == 1) fd = 0;

    if (p_rx_bytes != 0) {
        if (!(prx = lock_user(VERIFY_WRITE, p_rx_bytes, 4, 0)))
            return TARGET_EFAULT;
    } else prx = NULL;

    if (!(p = lock_user(VERIFY_WRITE, buf, count, 0)))
        return TARGET_EFAULT;
    if (count < 0) /* The kernel does this in rw_verify_area, if I understand correctly */
        return TARGET_EINVAL;

    if (count != 0) {
        do {
            ret = read(fd, p, count);
        } while ((ret == -1) && (errno == EINTR));
        if (ret >= 0)
            unlock_user(p, buf, ret);
        else return get_errno(ret);
    }

    /* if we recv 0 two times in a row exit */
    if (ret == 0)
    {
        if (zero_recv_hits > 0)
            exit_group(1);
        else
            zero_recv_hits++;
    }
    else
    {
        zero_recv_hits = 0;
    }

    if (prx != NULL) {
        __put_user(ret, prx);
        unlock_user(prx, p_rx_bytes, 4);
    }
    return 0;
}

static abi_long do_transmit(abi_long fd, abi_ulong buf, abi_long count, abi_ulong p_tx_bytes) {
    int ret = 0;
    abi_ulong *p; abi_long *ptx;

    /* adjust transmit to use stdout if it requests stdin */
    if (fd == 0) fd = 1;

    if (p_tx_bytes != 0) {
        if (!(ptx = lock_user(VERIFY_WRITE, p_tx_bytes, 4, 0)))
            return TARGET_EFAULT;
    } else ptx = NULL;

    if (!(p = lock_user(VERIFY_READ, buf, count, 1)))
        return TARGET_EFAULT;
    if (count < 0) /* The kernel does this in rw_verify_area, if I understand correctly */
        return TARGET_EINVAL;

    if (count != 0) {
        do {
            ret = write(fd, p, count);
        } while ((ret == -1) && (errno == EINTR));
        if (ret >= 0)
            unlock_user(p, buf, 0);
        else return get_errno(ret);
    }

    if (ptx != NULL) {
        __put_user(ret, ptx);
        unlock_user(ptx, p_tx_bytes, 4);
    }
    return 0;
}

static abi_long do_random(abi_ulong buf, abi_long count, abi_ulong p_rnd_out)
{
    /* DIFFERS FROM binfmt_cgc: 16-bits at a time here (rand returns 31 bits, not 32). */

    size_t size, i;
    uint16_t randval;
    int ret;
    abi_ulong *pout;
    if (p_rnd_out != 0) {
        if (!(pout = lock_user(VERIFY_WRITE, p_rnd_out, 4, 0)))
            return TARGET_EFAULT;
    } else pout = NULL;

    for (i = 0; i < count; i += sizeof(randval)) {
        /* CGC TODO: Should I worry about multi-threading? */
        _Static_assert(RAND_MAX >= INT16_MAX, "I rely on RAND_MAX giving at least 16 random bits");
        randval = 0x4141;
        size = ((count - i) < sizeof(randval)) ? (count - i) : sizeof(randval);
        if (size == 1) {
            ret = put_user_u8((uint8_t) randval, buf + i);
        } else if (size == 2) {
            ret = put_user_u16(randval, buf + i);
        } else {
            fprintf(stderr, "qemu: INTERNAL ERROR: I can only write 8 or 16 bits at a time! (asked for %zd)", size);
            exit(-37);
        }
        if (ret)
            return ret;
    }

    if (pout != NULL) {
        __put_user(count, pout);
        unlock_user(pout, p_rnd_out, 4);
    }
    return 0;
}

static abi_long do_allocate(abi_ulong len, abi_ulong exec, abi_ulong p_addr)
{
    int prot = PROT_READ | PROT_WRITE;
    abi_ulong *p;
    abi_long ret;

    if (exec)
        prot |= PROT_EXEC;

    if (p_addr != 0) {
        if (!(p = lock_user(VERIFY_WRITE, p_addr, 4, 0)))
            return TARGET_EFAULT;
    } else p = NULL; /* Believe it or not, binfmt_cgc allows this */

    ret = 0;

    abi_ulong aligned_len = ((len + 0xfff) / 0x1000) * 0x1000;
    abi_ulong mmap_ret = target_mmap((abi_ulong)0, aligned_len, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mmap_ret == -1)
        return get_errno(mmap_ret);
    if (mmap_ret == 0)
        return host_to_target_errno(errno);

    if (p != NULL) {
        __put_user(mmap_ret, p);
        unlock_user(p, p_addr, 4);
    }

    return ret;
}

static abi_long do_deallocate(abi_ulong start, abi_ulong len)
{
    abi_ulong aligned_len = ((len + 0xfff) / 0x1000) * 0x1000;
    return target_munmap(start, aligned_len);
}

#define USEC_PER_SEC 1000000L
static abi_long do_fdwait(abi_int n, abi_ulong rfd_addr, abi_ulong wfd_addr, abi_ulong target_tv_addr, abi_ulong p_readyfds)
{
    fd_set rfds, wfds;
    fd_set *rfds_ptr = NULL, *wfds_ptr = NULL;
    struct timeval tv, *tv_ptr;
    abi_long ret;

    abi_ulong *pready;
    if (p_readyfds != 0) { /* Believe it or not, binfmt_cgc allows this */
        if (!(pready = lock_user(VERIFY_WRITE, p_readyfds, 4, 0)))
            return TARGET_EFAULT;
    } else pready = NULL;


    if (target_tv_addr) {
        if (copy_from_user_timeval(&tv, target_tv_addr))
            return TARGET_EFAULT;
        tv_ptr = &tv;
        tv.tv_sec = tv.tv_sec + (tv.tv_usec / USEC_PER_SEC);
        tv.tv_usec %= USEC_PER_SEC;
        tv.tv_usec -= tv.tv_usec % 10000; /* gate to 0.01s */
    } else {
        tv_ptr = NULL;
    }
    ret = copy_from_user_fdset_ptr(&rfds, &rfds_ptr, rfd_addr, n);
    if (ret) {
        return ret;
    }
    ret = copy_from_user_fdset_ptr(&wfds, &wfds_ptr, wfd_addr, n);
    if (ret) {
        return ret;
    }

    /* XXX: Linux auto-adjusts the timeout parameter unless STICKY_TIMEOUTS is set:
     *      CGC binaries have that, but we don't need it (we just don't copy tv back). */
    do {
        ret = select(n, rfds_ptr, wfds_ptr, NULL, tv_ptr);
    } while ((ret == -1) && (errno == EINTR));
    if (ret == -1)
        return get_errno(ret);

    if (is_error(ret)) {
        fprintf(stderr, "qemu: INTERNAL ERROR: select returned an error value != -1 ("TARGET_ABI_FMT_ld") !", ret);
        exit(-39);
    }

    if (rfd_addr && copy_to_user_fdset(rfd_addr, &rfds, n))
        return TARGET_EFAULT;
    if (wfd_addr && copy_to_user_fdset(wfd_addr, &wfds, n))
        return TARGET_EFAULT;

    if (pready != NULL) {
        __put_user(ret, pready);
        unlock_user(pready, p_readyfds, 4);
    }
    return 0;
}


/* do_syscall() should always have a single exit point at the end so
   that actions, such as logging of syscall results, can be performed.
   All errnos that do_syscall() returns must be -TARGET_<errcode>. */
abi_long do_syscall(void *cpu_env, int num, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6, abi_long arg7,
                    abi_long arg8)
{
    /* CPUState *cpu = ENV_GET_CPU(cpu_env); */
    abi_long ret;

#ifdef DEBUG
    gemu_log("syscall %d", num);
#endif
    if(do_strace)
        print_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

    switch(num) {
    case TARGET_NR_receive:
        ret = do_receive(cpu_env, arg1, arg2, arg3, arg4);
        break;
    case TARGET_NR_transmit:
        ret = do_transmit(arg1, arg2, arg3, arg4);
        break;

    case TARGET_NR_fdwait:
        ret = do_fdwait(arg1, arg2, arg3, arg4, arg5);
        break;


    case TARGET_NR_allocate:
        ret = do_allocate(arg1, arg2, arg3);
        break;

    case TARGET_NR_deallocate:
        ret = do_deallocate(arg1, arg2);
        break;


    case TARGET_NR_terminate:
#ifdef TARGET_GPROF
        _mcleanup();
#endif
        gdb_exit(cpu_env, arg1);
        ret = get_errno(exit_group(arg1));
        break;


    case TARGET_NR_random:
        ret = do_random(arg1, arg2, arg3);
        break;


    default:
        gemu_log("qemu: Unsupported syscall: %d\n", num);
        ret = TARGET_ENOSYS;
        break;
    }
#ifdef DEBUG
    gemu_log(" = " TARGET_ABI_FMT_ld "\n", ret);
#endif
    if(do_strace)
        print_syscall_ret(num, ret);
    if (!((ret >= 0) && (ret <= 6))) { /* CGC syscalls return either 0 or an error */
        fprintf(stderr, "qemu: INTERNAL ERROR: syscall %d tried to return %d, but all CGC syscall return either 0 or one of the CGC_Exxx (positive) values.\n", num, ret);
        exit(-33);
    }
    return ret;
}
