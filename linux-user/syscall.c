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


#ifndef AFL
#ifdef __NR_exit_group
_syscall1(int,exit_group,int,error_code)
#endif
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

int report_bad_args = 0;
int enabled_double_empty_exiting = 0;

#ifdef AFL
int possibly_controlled_buf = 0;


int exit_group(int error_code) {
    if (possibly_controlled_buf)
        raise(SIGSEGV);

    syscall(__NR_exit_group, error_code);
}
#endif

#ifdef AFL
unsigned first_recv = 1;
#endif
static unsigned zero_recv_hits = 0;
#if defined(TRACER) || defined(AFL)
static unsigned first_recv_hit = false;
#endif

FILE *receive_count_fp = NULL;

#ifdef TRACER
char *predump_file = NULL;

static int predump_one(void *priv, target_ulong start,
    target_ulong end, unsigned long prot)
{
    FILE *f;
    target_ulong length;

    f = (FILE *)priv;

    length = end - start;

    fwrite(&start, sizeof(target_ulong), 1, f);
    fwrite(&end, sizeof(target_ulong), 1, f);
    fwrite(&prot, sizeof(target_ulong), 1, f);
    fwrite(&length, sizeof(target_ulong), 1, f);

    fwrite(g2h(start), length, 1, f);

    return 0;
}

static int do_predump(char *file, CPUX86State *env)
{
    FILE *f;

    f = fopen(file, "w");
    if (f == NULL) {
        perror("predump file open");
        return -1;
    }

    walk_memory_regions(f, predump_one);

    fwrite("HEAP", 4, 1, f);
    fwrite(&mmap_next_start, 4, 1, f);

    fwrite("REGS", 4, 1, f);
    /* write out registers */
    fwrite(&env->regs[R_EAX], 4, 1, f);
    fwrite(&env->regs[R_EBX], 4, 1, f);
    fwrite(&env->regs[R_ECX], 4, 1, f);
    fwrite(&env->regs[R_EDX], 4, 1, f);
    fwrite(&env->regs[R_ESI], 4, 1, f);
    fwrite(&env->regs[R_EDI], 4, 1, f);
    fwrite(&env->regs[R_EBP], 4, 1, f);
    fwrite(&env->regs[R_ESP], 4, 1, f);

    /* write out d flag */
    fwrite(&env->df, 4, 1, f);

    /* write out eip */
    fwrite(&env->eip, 4, 1, f);

    /* write out fp registers */
    fwrite(&env->fpregs[0], sizeof(FPReg), 1, f);
    fwrite(&env->fpregs[1], sizeof(FPReg), 1, f);
    fwrite(&env->fpregs[2], sizeof(FPReg), 1, f);
    fwrite(&env->fpregs[3], sizeof(FPReg), 1, f);
    fwrite(&env->fpregs[4], sizeof(FPReg), 1, f);
    fwrite(&env->fpregs[5], sizeof(FPReg), 1, f);
    fwrite(&env->fpregs[6], sizeof(FPReg), 1, f);
    fwrite(&env->fpregs[7], sizeof(FPReg), 1, f);

    /* write out fp tags */
    fwrite(&env->fptags[0], 1, 1, f);
    fwrite(&env->fptags[1], 1, 1, f);
    fwrite(&env->fptags[2], 1, 1, f);
    fwrite(&env->fptags[3], 1, 1, f);
    fwrite(&env->fptags[4], 1, 1, f);
    fwrite(&env->fptags[5], 1, 1, f);
    fwrite(&env->fptags[6], 1, 1, f);
    fwrite(&env->fptags[7], 1, 1, f);

    /* ftop */
    fwrite(&env->fpstt, 4, 1, f);

    /* sseround */
    fwrite(&env->mxcsr, 4, 1, f);

    /* write out xmm registers */
    fwrite(&env->xmm_regs[0], 16, 1, f);
    fwrite(&env->xmm_regs[1], 16, 1, f);
    fwrite(&env->xmm_regs[2], 16, 1, f);
    fwrite(&env->xmm_regs[3], 16, 1, f);
    fwrite(&env->xmm_regs[4], 16, 1, f);
    fwrite(&env->xmm_regs[5], 16, 1, f);
    fwrite(&env->xmm_regs[6], 16, 1, f);
    fwrite(&env->xmm_regs[7], 16, 1, f);

    fclose(f);
    return 0;
}
#endif /* TRACER */



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

struct sinkhole_entry {
    abi_ulong addr;
    size_t length;
    struct sinkhole_entry *next;
    struct sinkhole_entry *prev;
};

struct sinkhole_entry *sinkhole_head = NULL;

void add_sinkhole(abi_ulong, size_t);
abi_ulong get_max_sinkhole(size_t);
void print_sinkholes(void);

void add_sinkhole(abi_ulong a, size_t length) {
    struct sinkhole_entry *nse;

    nse = malloc(sizeof(struct sinkhole_entry));
    nse->addr = a;
    nse->length = length;
    nse->next = NULL;
    nse->prev = NULL;

    /* head insertion */
    if (sinkhole_head) {

        nse->next = sinkhole_head;
        nse->prev = NULL;

        if (sinkhole_head->prev) {
            printf("ERROR: sinkhole_head->prev should always be NULL\n");
        }

        sinkhole_head->prev = nse;

        sinkhole_head = nse;
    } else {
      sinkhole_head = nse;
    }
}

abi_ulong get_max_sinkhole(size_t length) {
    struct sinkhole_entry *current, *max;
    abi_ulong max_addr = 0;

    current = sinkhole_head;
    while(current) {
        if (current->length >= length && current->addr > max_addr) {
            max_addr = current->addr; 
            max = current;
        }
        current = current->next;
    }

    if (!max_addr)
        return 0;

    size_t remaining = max->length - length;
    max_addr = max->addr + remaining;
    max->length = remaining;

    /* remove node if it's empty */
    if (!max->length) {
        if (max->prev) {
            max->prev->next = max->next;
        }
        if (max->next) {
            max->next->prev = max->prev;
        }
        if (sinkhole_head == max) {
            sinkhole_head = max->next;
        }
        free(max);
    }

    return max_addr;
}

void print_sinkholes(void) {
    struct sinkhole_entry *current;
    current = sinkhole_head;
    while (current) {
        printf("addr: %x, length: %x\n", current->addr, (unsigned int)current->length);
        current = current->next;
    }
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

extern int bitflip;


/* The functions are approximate copies of the kernel code */
/* Note: usually even qemu's original code does not call unlock_user on errors.
 *       (And unless DEBUG_REMAP is defined it's a no-op anyway.) */

#if defined(TRACER) || defined(AFL)
static abi_long do_receive(CPUX86State *env, abi_long fd, abi_ulong buf, abi_long count, abi_ulong p_rx_bytes) {
#else
static abi_long do_receive(abi_long fd, abi_ulong buf, abi_long count, abi_ulong p_rx_bytes) {
#endif
#ifdef AFL
    /* start the forkserver on the first call to receive to save even more time */
    if (first_recv)
    {
        afl_setup();
        afl_forkserver(env);
        first_recv = 0;
    }
#endif

    int ret = 0;
    abi_ulong *p; abi_long *prx;

    /* adjust receive to use stdin if it requests stdout */
    if (fd == 1) fd = 0;

#if defined(TRACER) || defined(AFL)
    /* predump the state for cle */
    if (!first_recv_hit)
    {
#ifdef TRACER
        if (predump_file)
        {
            do_predump(predump_file, env);
            exit_group(0);
        }
#endif
        first_recv_hit = true;
    }
#endif

    if (p_rx_bytes != 0) {
        if (!(prx = lock_user(VERIFY_WRITE, p_rx_bytes, 4, 0))) {

            return TARGET_EFAULT;
        }
    } else prx = NULL;

    /* Shortens the count to valid pages only.
     * TODO: check, see translate_all.c */
    __attribute__((unused)) const abi_long req_count = count;
    count = valid_len(buf, count, PAGE_READ|PAGE_WRITE);
#ifdef DEBUG_LENIENT_LENGTHS
    if (count < req_count)
        fprintf(stderr, "FOR_CGC: Pre-shortening receive count=%d to %d\n", req_count, count);
#endif

    if (!(p = lock_user(VERIFY_WRITE, buf, count, 0))) {
#ifdef AFL
            possibly_controlled_buf = 1;
#endif
            if (report_bad_args)
                raise(SIGSEGV);

        return TARGET_EFAULT;
    }
    if (count < 0) /* The kernel does this in rw_verify_area, if I understand correctly */
        return TARGET_EINVAL;

    if (count != 0) {
        do {
            ret = read(fd, p, count);
        } while ((ret == -1) && (errno == EINTR));
        if (ret >= 0) {
            if (bitflip) {
                int i;
                for (i = 0; i < ret; i++){
                    unsigned char* pc = (unsigned char*)p;
                    if(pc[i]==0x00){
                        pc[i] = 0x43;
                    }else if(pc[i]==0x43){
                        pc[i] = 0x0a;
                    }else if(pc[i]==0xa){
                        pc[i] = 0x31;
                    }else if(pc[i]==0x31){
                        pc[i] = 0x00;
                    }
                }
            }
            if (receive_count_fp) {
                fprintf(receive_count_fp, "%u %u\n", ret, count);
            }
            unlock_user(p, buf, ret);
        } else return get_errno(ret);
    }


    if (enabled_double_empty_exiting) {
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

    /* Shortens the count to valid pages only.
     * TODO: check, see translate_all.c */
    __attribute__((unused)) const abi_long req_count = count;
    count = valid_len(buf, count, PAGE_READ);
#ifdef DEBUG_LENIENT_LENGTHS
    if (count < req_count)
        fprintf(stderr, "FOR_CGC: Pre-shortening transmit count=%d to %d\n", req_count, count);
#endif

    if (!(p = lock_user(VERIFY_READ, buf, count, 1))) {
#ifdef AFL
        possibly_controlled_buf = 1;
#endif
        if (report_bad_args)
            raise(SIGSEGV);

        return TARGET_EFAULT;
    }
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

    /* Shortens the count to valid pages only.
     * TODO: check, see translate_all.c */
    __attribute__((unused)) const abi_long req_count = count;
    count = valid_len(buf, count, PAGE_READ|PAGE_WRITE);
#ifdef DEBUG_LENIENT_LENGTHS
    if (count < req_count)
        fprintf(stderr, "FOR_CGC: Pre-shortening random() count=%d to %d\n", req_count, count);
#endif

    for (i = 0; i < count; i += sizeof(randval)) {
        _Static_assert(RAND_MAX >= INT16_MAX, "I rely on RAND_MAX giving at least 16 random bits");
        randval = 0x4141;
        if (seed_passed)
            randval = rand() & 0xFFFFu;
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

    if (len == 0) // ABI-specified, vagrant returns this before EFAULT
        return TARGET_EINVAL;

    if (exec)
        prot |= PROT_EXEC;

    if (p_addr != 0) {
        if (!(p = lock_user(VERIFY_WRITE, p_addr, 4, 0)))
            return TARGET_EFAULT;
    } else p = NULL; /* Believe it or not, binfmt_cgc allows this */

    ret = 0;
    abi_ulong chosen = 0;
    abi_ulong sinkhole_chosen = 0;
    abi_ulong aligned_len = ((len + 0xfff) / 0x1000) * 0x1000;

    /* check sinkholes */
    chosen = sinkhole_chosen = get_max_sinkhole(aligned_len);
    if (!chosen)
        chosen = mmap_next_start - aligned_len;

    abi_ulong mmap_ret = target_mmap((abi_ulong)chosen, aligned_len, prot, MAP_ANONYMOUS | MAP_PRIVATE| MAP_FIXED, -1, 0);
    if (mmap_ret == -1)
        return get_errno(mmap_ret);
    if (mmap_ret == 0)
        return host_to_target_errno(errno);

    if (!sinkhole_chosen)
        mmap_next_start = chosen;

    if (p != NULL) {
        __put_user(mmap_ret, p);
        unlock_user(p, p_addr, 4);
    }

    return ret;
}

static abi_long do_deallocate(abi_ulong start, abi_ulong len)
{
    abi_long ret;
    abi_ulong aligned_len = ((len + 0xfff) / 0x1000) * 0x1000;
    abi_ulong allowed_length = 0;

    // ABI-specified: EINVAL on misaligned || len == 0
    if (((start % 4096) != 0) || (len == 0))
        return TARGET_EINVAL;
    if ((start + aligned_len) > reserved_va) // TODO: "outside the valid address range"...
        return TARGET_EINVAL;

    // HACK! check to see if the page is mapped, if not deallocate fails
    while ((lock_user(VERIFY_WRITE, start, allowed_length + 0x1000, 0)) && allowed_length < aligned_len) {
        allowed_length += 0x1000;
    }

    if (allowed_length == 0) {
        return 0; // Apparently that's what the ABI does
    }

    aligned_len = allowed_length;

    // No deallocating the flag page! (check from binfmt_cgc.c)
    if (!((start + aligned_len) <= 0x4347c000 || start >= (0x4347c000 + 4096)))
        return TARGET_EINVAL;

    ret = target_munmap(start, aligned_len);

    /* target_munmap returns either 0 or the errno * -1 */
    if (ret < 0)
        return host_to_target_errno(ret * -1);

    if (start == mmap_next_start)
        mmap_next_start += aligned_len;
    else /* add a sinkhole */
        add_sinkhole(start, aligned_len);
    
    return ret;
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
#if defined(TRACER) || defined(AFL)
        ret = do_receive(cpu_env, arg1, arg2, arg3, arg4);
#else
        ret = do_receive(arg1, arg2, arg3, arg4);
#endif
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
