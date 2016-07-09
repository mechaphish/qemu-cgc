/* values for the selectors copied from the VM, out of caution */
#define __USER_CS	(0x73)
#define __USER_DS	(0x7B)

struct target_pt_regs {
	long ebx;
	long ecx;
	long edx;
	long esi;
	long edi;
	long ebp;
	long eax;
	int  xds;
	int  xes;
	long orig_eax;
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};

/* Increased to accomodate the high values, same as arch/x86/include/asm/segment.h */
#define TARGET_GDT_ENTRIES             32

#define UNAME_MACHINE "i686"
#define UNAME_MINIMUM_RELEASE "2.6.32"

#define TARGET_CLONE_BACKWARDS
#define TARGET_MINSIGSTKSZ 2048
#define TARGET_MLOCKALL_MCL_CURRENT 1
#define TARGET_MLOCKALL_MCL_FUTURE  2
