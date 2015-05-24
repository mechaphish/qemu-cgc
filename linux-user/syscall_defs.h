/* common syscall defines for all architectures */

/* Note: although the syscall numbers change between architectures,
   most of them stay the same, so we handle it by putting ifdefs if
   necessary */

#ifndef SYSCALL_DEFS_H
#define SYSCALL_DEFS_H 1


#include "syscall_nr.h"


struct target_timeval {
    abi_long tv_sec;
    abi_long tv_usec;
};

typedef abi_long target_clock_t;



/* mostly generic signal stuff */
#define TARGET_SIG_DFL	((abi_long)0)	/* default signal handling */
#define TARGET_SIG_IGN	((abi_long)1)	/* ignore signal */
#define TARGET_SIG_ERR	((abi_long)-1)	/* error return from signal */

#define TARGET_NSIG	   64
#define TARGET_NSIG_BPW	   TARGET_ABI_BITS
#define TARGET_NSIG_WORDS  (TARGET_NSIG / TARGET_NSIG_BPW)

typedef struct {
    abi_ulong sig[TARGET_NSIG_WORDS];
} target_sigset_t;

#ifdef BSWAP_NEEDED
static inline void tswap_sigset(target_sigset_t *d, const target_sigset_t *s)
{
    int i;
    for(i = 0;i < TARGET_NSIG_WORDS; i++)
        d->sig[i] = tswapal(s->sig[i]);
}
#else
static inline void tswap_sigset(target_sigset_t *d, const target_sigset_t *s)
{
    *d = *s;
}
#endif

static inline void target_siginitset(target_sigset_t *d, abi_ulong set)
{
    int i;
    d->sig[0] = set;
    for(i = 1;i < TARGET_NSIG_WORDS; i++)
        d->sig[i] = 0;
}

void host_to_target_sigset(target_sigset_t *d, const sigset_t *s);
void target_to_host_sigset(sigset_t *d, const target_sigset_t *s);
void host_to_target_old_sigset(abi_ulong *old_sigset,
                               const sigset_t *sigset);
void target_to_host_old_sigset(sigset_t *sigset,
                               const abi_ulong *old_sigset);
struct target_sigaction;
int do_sigaction(int sig, const struct target_sigaction *act,
                 struct target_sigaction *oact);

#if defined(TARGET_I386) || defined(TARGET_ARM) || defined(TARGET_SPARC) \
    || defined(TARGET_PPC) || defined(TARGET_MIPS) || defined(TARGET_SH4) \
    || defined(TARGET_M68K) || defined(TARGET_ALPHA) || defined(TARGET_CRIS) \
    || defined(TARGET_MICROBLAZE) || defined(TARGET_UNICORE32) \
    || defined(TARGET_S390X) || defined(TARGET_OPENRISC)

#if defined(TARGET_SPARC)
#define TARGET_SA_NOCLDSTOP    8u
#define TARGET_SA_NOCLDWAIT    0x100u
#define TARGET_SA_SIGINFO      0x200u
#define TARGET_SA_ONSTACK      1u
#define TARGET_SA_RESTART      2u
#define TARGET_SA_NODEFER      0x20u
#define TARGET_SA_RESETHAND    4u
#elif defined(TARGET_MIPS)
#define TARGET_SA_NOCLDSTOP	0x00000001
#define TARGET_SA_NOCLDWAIT	0x00010000
#define TARGET_SA_SIGINFO	0x00000008
#define TARGET_SA_ONSTACK	0x08000000
#define TARGET_SA_NODEFER	0x40000000
#define TARGET_SA_RESTART	0x10000000
#define TARGET_SA_RESETHAND	0x80000000
#if !defined(TARGET_ABI_MIPSN32) && !defined(TARGET_ABI_MIPSN64)
#define TARGET_SA_RESTORER	0x04000000	/* Only for O32 */
#endif
#elif defined(TARGET_OPENRISC)
#define TARGET_SA_NOCLDSTOP    0x00000001
#define TARGET_SA_NOCLDWAIT    0x00000002
#define TARGET_SA_SIGINFO      0x00000004
#define TARGET_SA_ONSTACK      0x08000000
#define TARGET_SA_RESTART      0x10000000
#define TARGET_SA_NODEFER      0x40000000
#define TARGET_SA_RESETHAND    0x80000000
#elif defined(TARGET_ALPHA)
#define TARGET_SA_ONSTACK	0x00000001
#define TARGET_SA_RESTART	0x00000002
#define TARGET_SA_NOCLDSTOP	0x00000004
#define TARGET_SA_NODEFER	0x00000008
#define TARGET_SA_RESETHAND	0x00000010
#define TARGET_SA_NOCLDWAIT	0x00000020 /* not supported yet */
#define TARGET_SA_SIGINFO	0x00000040
#else
#define TARGET_SA_NOCLDSTOP	0x00000001
#define TARGET_SA_NOCLDWAIT	0x00000002 /* not supported yet */
#define TARGET_SA_SIGINFO	0x00000004
#define TARGET_SA_ONSTACK	0x08000000
#define TARGET_SA_RESTART	0x10000000
#define TARGET_SA_NODEFER	0x40000000
#define TARGET_SA_RESETHAND	0x80000000
#define TARGET_SA_RESTORER	0x04000000
#endif

#if defined(TARGET_ALPHA)

#define TARGET_SIGHUP            1
#define TARGET_SIGINT            2
#define TARGET_SIGQUIT           3
#define TARGET_SIGILL            4
#define TARGET_SIGTRAP           5
#define TARGET_SIGABRT           6
#define TARGET_SIGSTKFLT         7 /* actually SIGEMT */
#define TARGET_SIGFPE            8
#define TARGET_SIGKILL           9
#define TARGET_SIGBUS           10
#define TARGET_SIGSEGV          11
#define TARGET_SIGSYS           12
#define TARGET_SIGPIPE          13
#define TARGET_SIGALRM          14
#define TARGET_SIGTERM          15
#define TARGET_SIGURG           16
#define TARGET_SIGSTOP          17
#define TARGET_SIGTSTP          18
#define TARGET_SIGCONT          19
#define TARGET_SIGCHLD          20
#define TARGET_SIGTTIN          21
#define TARGET_SIGTTOU          22
#define TARGET_SIGIO            23
#define TARGET_SIGXCPU          24
#define TARGET_SIGXFSZ          25
#define TARGET_SIGVTALRM        26
#define TARGET_SIGPROF          27
#define TARGET_SIGWINCH         28
#define TARGET_SIGPWR           29 /* actually SIGINFO */
#define TARGET_SIGUSR1          30
#define TARGET_SIGUSR2          31
#define TARGET_SIGRTMIN         32

#define TARGET_SIG_BLOCK         1
#define TARGET_SIG_UNBLOCK       2
#define TARGET_SIG_SETMASK       3

#elif defined(TARGET_SPARC)

#define TARGET_SIGHUP		 1
#define TARGET_SIGINT		 2
#define TARGET_SIGQUIT		 3
#define TARGET_SIGILL		 4
#define TARGET_SIGTRAP		 5
#define TARGET_SIGABRT		 6
#define TARGET_SIGIOT		 6
#define TARGET_SIGSTKFLT	 7 /* actually EMT */
#define TARGET_SIGFPE		 8
#define TARGET_SIGKILL		 9
#define TARGET_SIGBUS		10
#define TARGET_SIGSEGV		11
#define TARGET_SIGSYS		12
#define TARGET_SIGPIPE		13
#define TARGET_SIGALRM		14
#define TARGET_SIGTERM		15
#define TARGET_SIGURG		16
#define TARGET_SIGSTOP		17
#define TARGET_SIGTSTP		18
#define TARGET_SIGCONT		19
#define TARGET_SIGCHLD		20
#define TARGET_SIGTTIN		21
#define TARGET_SIGTTOU		22
#define TARGET_SIGIO		23
#define TARGET_SIGXCPU		24
#define TARGET_SIGXFSZ		25
#define TARGET_SIGVTALRM	26
#define TARGET_SIGPROF		27
#define TARGET_SIGWINCH	        28
#define TARGET_SIGPWR		29
#define TARGET_SIGUSR1		30
#define TARGET_SIGUSR2		31
#define TARGET_SIGRTMIN         32

#define TARGET_SIG_BLOCK          0x01 /* for blocking signals */
#define TARGET_SIG_UNBLOCK        0x02 /* for unblocking signals */
#define TARGET_SIG_SETMASK        0x04 /* for setting the signal mask */

#elif defined(TARGET_MIPS)

#define TARGET_SIGHUP		 1	/* Hangup (POSIX).  */
#define TARGET_SIGINT		 2	/* Interrupt (ANSI).  */
#define TARGET_SIGQUIT		 3	/* Quit (POSIX).  */
#define TARGET_SIGILL		 4	/* Illegal instruction (ANSI).  */
#define TARGET_SIGTRAP		 5	/* Trace trap (POSIX).  */
#define TARGET_SIGIOT		 6	/* IOT trap (4.2 BSD).  */
#define TARGET_SIGABRT		 TARGET_SIGIOT	/* Abort (ANSI).  */
#define TARGET_SIGEMT		 7
#define TARGET_SIGSTKFLT	 7 /* XXX: incorrect */
#define TARGET_SIGFPE		 8	/* Floating-point exception (ANSI).  */
#define TARGET_SIGKILL		 9	/* Kill, unblockable (POSIX).  */
#define TARGET_SIGBUS		10	/* BUS error (4.2 BSD).  */
#define TARGET_SIGSEGV		11	/* Segmentation violation (ANSI).  */
#define TARGET_SIGSYS		12
#define TARGET_SIGPIPE		13	/* Broken pipe (POSIX).  */
#define TARGET_SIGALRM		14	/* Alarm clock (POSIX).  */
#define TARGET_SIGTERM		15	/* Termination (ANSI).  */
#define TARGET_SIGUSR1		16	/* User-defined signal 1 (POSIX).  */
#define TARGET_SIGUSR2		17	/* User-defined signal 2 (POSIX).  */
#define TARGET_SIGCHLD		18	/* Child status has changed (POSIX).  */
#define TARGET_SIGCLD		TARGET_SIGCHLD	/* Same as TARGET_SIGCHLD (System V).  */
#define TARGET_SIGPWR		19	/* Power failure restart (System V).  */
#define TARGET_SIGWINCH	20	/* Window size change (4.3 BSD, Sun).  */
#define TARGET_SIGURG		21	/* Urgent condition on socket (4.2 BSD).  */
#define TARGET_SIGIO		22	/* I/O now possible (4.2 BSD).  */
#define TARGET_SIGPOLL		TARGET_SIGIO	/* Pollable event occurred (System V).  */
#define TARGET_SIGSTOP		23	/* Stop, unblockable (POSIX).  */
#define TARGET_SIGTSTP		24	/* Keyboard stop (POSIX).  */
#define TARGET_SIGCONT		25	/* Continue (POSIX).  */
#define TARGET_SIGTTIN		26	/* Background read from tty (POSIX).  */
#define TARGET_SIGTTOU		27	/* Background write to tty (POSIX).  */
#define TARGET_SIGVTALRM	28	/* Virtual alarm clock (4.2 BSD).  */
#define TARGET_SIGPROF		29	/* Profiling alarm clock (4.2 BSD).  */
#define TARGET_SIGXCPU		30	/* CPU limit exceeded (4.2 BSD).  */
#define TARGET_SIGXFSZ		31	/* File size limit exceeded (4.2 BSD).  */
#define TARGET_SIGRTMIN         32

#define TARGET_SIG_BLOCK	1	/* for blocking signals */
#define TARGET_SIG_UNBLOCK	2	/* for unblocking signals */
#define TARGET_SIG_SETMASK	3	/* for setting the signal mask */

#else

/* OpenRISC Using the general signals */
#define TARGET_SIGHUP		 1
#define TARGET_SIGINT		 2
#define TARGET_SIGQUIT		 3
#define TARGET_SIGILL		 4
#define TARGET_SIGTRAP		 5
#define TARGET_SIGABRT		 6
#define TARGET_SIGIOT		 6
#define TARGET_SIGBUS		 7
#define TARGET_SIGFPE		 8
#define TARGET_SIGKILL		 9
#define TARGET_SIGUSR1		10
#define TARGET_SIGSEGV		11
#define TARGET_SIGUSR2		12
#define TARGET_SIGPIPE		13
#define TARGET_SIGALRM		14
#define TARGET_SIGTERM		15
#define TARGET_SIGSTKFLT	16
#define TARGET_SIGCHLD		17
#define TARGET_SIGCONT		18
#define TARGET_SIGSTOP		19
#define TARGET_SIGTSTP		20
#define TARGET_SIGTTIN		21
#define TARGET_SIGTTOU		22
#define TARGET_SIGURG		23
#define TARGET_SIGXCPU		24
#define TARGET_SIGXFSZ		25
#define TARGET_SIGVTALRM	26
#define TARGET_SIGPROF		27
#define TARGET_SIGWINCH	        28
#define TARGET_SIGIO		29
#define TARGET_SIGPWR		30
#define TARGET_SIGSYS		31
#define TARGET_SIGRTMIN         32

#define TARGET_SIG_BLOCK          0    /* for blocking signals */
#define TARGET_SIG_UNBLOCK        1    /* for unblocking signals */
#define TARGET_SIG_SETMASK        2    /* for setting the signal mask */

#endif

#if defined(TARGET_ALPHA)
struct target_old_sigaction {
    abi_ulong _sa_handler;
    abi_ulong sa_mask;
    int32_t sa_flags;
};

struct target_rt_sigaction {
    abi_ulong _sa_handler;
    abi_ulong sa_flags;
    target_sigset_t sa_mask;
};

/* This is the struct used inside the kernel.  The ka_restorer
   field comes from the 5th argument to sys_rt_sigaction.  */
struct target_sigaction {
    abi_ulong _sa_handler;
    abi_ulong sa_flags;
    target_sigset_t sa_mask;
    abi_ulong sa_restorer;
};
#elif defined(TARGET_MIPS)
struct target_sigaction {
	uint32_t	sa_flags;
#if defined(TARGET_ABI_MIPSN32)
	uint32_t	_sa_handler;
#else
	abi_ulong	_sa_handler;
#endif
	target_sigset_t	sa_mask;
};
#else
struct target_old_sigaction {
        abi_ulong _sa_handler;
        abi_ulong sa_mask;
        abi_ulong sa_flags;
        abi_ulong sa_restorer;
};

struct target_sigaction {
        abi_ulong _sa_handler;
        abi_ulong sa_flags;
        abi_ulong sa_restorer;
        target_sigset_t sa_mask;
};
#endif

typedef union target_sigval {
	int sival_int;
        abi_ulong sival_ptr;
} target_sigval_t;
#if 0
#if defined (TARGET_SPARC)
typedef struct {
	struct {
		abi_ulong psr;
		abi_ulong pc;
		abi_ulong npc;
		abi_ulong y;
		abi_ulong u_regs[16]; /* globals and ins */
	}		si_regs;
	int		si_mask;
} __siginfo_t;

typedef struct {
	unsigned   long si_float_regs [32];
	unsigned   long si_fsr;
	unsigned   long si_fpqdepth;
	struct {
		unsigned long *insn_addr;
		unsigned long insn;
	} si_fpqueue [16];
} __siginfo_fpu_t;
#endif
#endif

#define TARGET_SI_MAX_SIZE	128

#if TARGET_ABI_BITS == 32
#define TARGET_SI_PREAMBLE_SIZE (3 * sizeof(int))
#else
#define TARGET_SI_PREAMBLE_SIZE (4 * sizeof(int))
#endif

#define TARGET_SI_PAD_SIZE ((TARGET_SI_MAX_SIZE - TARGET_SI_PREAMBLE_SIZE) / sizeof(int))

typedef struct target_siginfo {
#ifdef TARGET_MIPS
	int si_signo;
	int si_code;
	int si_errno;
#else
	int si_signo;
	int si_errno;
	int si_code;
#endif

	union {
		int _pad[TARGET_SI_PAD_SIZE];

		/* kill() */
		struct {
			pid_t _pid;		/* sender's pid */
			uid_t _uid;		/* sender's uid */
		} _kill;

		/* POSIX.1b timers */
		struct {
			unsigned int _timer1;
			unsigned int _timer2;
		} _timer;

		/* POSIX.1b signals */
		struct {
			pid_t _pid;		/* sender's pid */
			uid_t _uid;		/* sender's uid */
			target_sigval_t _sigval;
		} _rt;

		/* SIGCHLD */
		struct {
			pid_t _pid;		/* which child */
			uid_t _uid;		/* sender's uid */
			int _status;		/* exit code */
			target_clock_t _utime;
                        target_clock_t _stime;
		} _sigchld;

		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS */
		struct {
			abi_ulong _addr; /* faulting insn/memory ref. */
		} _sigfault;

		/* SIGPOLL */
		struct {
			int _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
			int _fd;
		} _sigpoll;
	} _sifields;
} target_siginfo_t;

/*
 * si_code values
 * Digital reserves positive values for kernel-generated signals.
 */
#define TARGET_SI_USER		0	/* sent by kill, sigsend, raise */
#define TARGET_SI_KERNEL	0x80	/* sent by the kernel from somewhere */
#define TARGET_SI_QUEUE	-1		/* sent by sigqueue */
#define TARGET_SI_TIMER -2              /* sent by timer expiration */
#define TARGET_SI_MESGQ	-3		/* sent by real time mesq state change */
#define TARGET_SI_ASYNCIO	-4	/* sent by AIO completion */
#define TARGET_SI_SIGIO	-5		/* sent by queued SIGIO */

/*
 * SIGILL si_codes
 */
#define TARGET_ILL_ILLOPC	(1)	/* illegal opcode */
#define TARGET_ILL_ILLOPN	(2)	/* illegal operand */
#define TARGET_ILL_ILLADR	(3)	/* illegal addressing mode */
#define TARGET_ILL_ILLTRP	(4)	/* illegal trap */
#define TARGET_ILL_PRVOPC	(5)	/* privileged opcode */
#define TARGET_ILL_PRVREG	(6)	/* privileged register */
#define TARGET_ILL_COPROC	(7)	/* coprocessor error */
#define TARGET_ILL_BADSTK	(8)	/* internal stack error */

/*
 * SIGFPE si_codes
 */
#define TARGET_FPE_INTDIV      (1)  /* integer divide by zero */
#define TARGET_FPE_INTOVF      (2)  /* integer overflow */
#define TARGET_FPE_FLTDIV      (3)  /* floating point divide by zero */
#define TARGET_FPE_FLTOVF      (4)  /* floating point overflow */
#define TARGET_FPE_FLTUND      (5)  /* floating point underflow */
#define TARGET_FPE_FLTRES      (6)  /* floating point inexact result */
#define TARGET_FPE_FLTINV      (7)  /* floating point invalid operation */
#define TARGET_FPE_FLTSUB      (8)  /* subscript out of range */
#define TARGET_NSIGFPE         8

/*
 * SIGSEGV si_codes
 */
#define TARGET_SEGV_MAPERR     (1)  /* address not mapped to object */
#define TARGET_SEGV_ACCERR     (2)  /* invalid permissions for mapped object */

/*
 * SIGBUS si_codes
 */
#define TARGET_BUS_ADRALN       (1)	/* invalid address alignment */
#define TARGET_BUS_ADRERR       (2)	/* non-existent physical address */
#define TARGET_BUS_OBJERR       (3)	/* object specific hardware error */

/*
 * SIGTRAP si_codes
 */
#define TARGET_TRAP_BRKPT	(1)	/* process breakpoint */
#define TARGET_TRAP_TRACE	(2)	/* process trace trap */

#endif /* defined(TARGET_I386) || defined(TARGET_ARM) */


#include "errno_defs.h"

#endif
