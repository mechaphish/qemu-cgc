#include <stdio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sched.h>
#include "qemu.h"

int do_strace=0;


static void
print_fdset(int n, abi_ulong target_fds_addr)
{
    int i;

    gemu_log("[");
    if( target_fds_addr ) {
        abi_long *target_fds;

        target_fds = lock_user(VERIFY_READ,
                               target_fds_addr,
                               sizeof(*target_fds)*(n / TARGET_ABI_BITS + 1),
                               1);

        if (!target_fds)
            return;

        for (i=n; i>=0; i--) {
            if ((tswapal(target_fds[i / TARGET_ABI_BITS]) >> (i & (TARGET_ABI_BITS - 1))) & 1)
                gemu_log("%d,", i );
            }
        unlock_user(target_fds, target_fds_addr, 0);
    }
    gemu_log("]");
}


/*
 * print_xxx utility functions.  These are used to print syscall
 * parameters in certain format.  All of these have parameter
 * named 'last'.  This parameter is used to add comma to output
 * when last == 0.
 */

static const char *
get_comma(int last)
{
    return ((last) ? "" : ", ");
}

/*
 * Prints out raw parameter using given format.  Caller needs
 * to do byte swapping if needed.
 */
static void
print_raw_param(const char *fmt, abi_long param, int last)
{
    char format[64];

    (void) snprintf(format, sizeof (format), "%s%s", fmt, get_comma(last));
    gemu_log(format, param);
}

static void
print_pointer(abi_long p, int last)
{
    if (p == 0)
        gemu_log("NULL%s", get_comma(last));
    else
        gemu_log("0x" TARGET_ABI_FMT_lx "%s", p, get_comma(last));
}

static void
print_timeval(abi_ulong tv_addr, int last)
{
    if( tv_addr ) {
        struct target_timeval *tv;

        tv = lock_user(VERIFY_READ, tv_addr, sizeof(*tv), 1);
        if (!tv)
            return;
        gemu_log("{" TARGET_ABI_FMT_ld "," TARGET_ABI_FMT_ld "}%s",
            tswapal(tv->tv_sec), tswapal(tv->tv_usec), get_comma(last));
        unlock_user(tv, tv_addr, 0);
    } else
        gemu_log("NULL%s", get_comma(last));
}


/*
 * The public interface to this module.
 */
void
print_syscall(int num,
              abi_long arg1, abi_long arg2, abi_long arg3,
              abi_long arg4, abi_long arg5, abi_long arg6)
{
    gemu_log("%d ", getpid() );
    switch (num) {
    case TARGET_NR_terminate:
        gemu_log("_terminate(%lu)", (unsigned long) arg1);
        break;
    case TARGET_NR_transmit:
        gemu_log("transmit(fd=%ld, ", (long) arg1);
        gemu_log("buf="); print_pointer(arg2, 0);
        print_raw_param("count=%d", arg3, 0);
        gemu_log("tx_bytes="); print_pointer(arg4, 1); /* CGC TODO: print on return */
        gemu_log(")");
        break;
    case TARGET_NR_receive:
        gemu_log("receive(fd=%ld, ", (long) arg1);
        gemu_log("buf="); print_pointer(arg2, 0); /* CGC TODO: print on return */
        print_raw_param("count=%d", arg3, 0);
        gemu_log("rx_bytes="); print_pointer(arg4, 1); /* CGC TODO: print on return */
        gemu_log(")");
        break;
    case TARGET_NR_fdwait:
        gemu_log("fdwait(nfds=%ld, ", (long) arg1);
        print_fdset(arg1, arg2); gemu_log(", ");
        print_fdset(arg1, arg3); gemu_log(", ");
        print_timeval(arg4, 0);
        print_pointer(arg5, 1); /* CGC TODO: print on return (including the fdsets) */
        gemu_log(")");
        break;
    case TARGET_NR_allocate:
        gemu_log("allocate(");
        print_raw_param("length=%d", arg1, 0);
        gemu_log(arg2 ? "rwX (EXECUTABLE)" : "rw"); gemu_log(", ");
        print_pointer(arg3, 1); /* CGC TODO: print on return */
        gemu_log(")");
        break;
    case TARGET_NR_deallocate:
        gemu_log("deallocate(");
        print_pointer(arg1, 0);
        print_raw_param("length=%d", arg2, 1);
        gemu_log(")");
        break;
    case TARGET_NR_random:
        gemu_log("random(");
        gemu_log("buf="); print_pointer(arg1, 0); /* CGC TODO: print on return */
        print_raw_param("count=%d", arg2, 0);
        gemu_log("bytes_written="); print_pointer(arg3, 0); /* CGC TODO: print on return */
        gemu_log(")");
        break;
    default:
        gemu_log("*!*!* Unknown syscall %d *!*!*\n", num);
    }
}


void
print_syscall_ret(int num, abi_long ret)
{
    /* CGC TODO: Print the result buffers */
#define MEANING(v) case v: meaning = " ("#v")"; break;
    const char *meaning;
    switch (ret) {
        MEANING(TARGET_EBADF)
        MEANING(TARGET_EFAULT)
        MEANING(TARGET_EINVAL)
        MEANING(TARGET_ENOMEM)
        MEANING(TARGET_ENOSYS)
        MEANING(TARGET_EPIPE)
    case 0:
        meaning = "";
        break;
    default:
        meaning = " *!*!* IMPOSSIBLE RETURN VALUE *!*!*";
    }
    gemu_log(" = " TARGET_ABI_FMT_ld "%s\n", ret, meaning);
}
