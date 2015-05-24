/* default linux values for the selectors */
#define __USER_CS	(0x23)
#define __USER_DS	(0x2B)

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

#define TARGET_GDT_ENTRIES             9
#define TARGET_GDT_ENTRY_TLS_ENTRIES   3
#define TARGET_GDT_ENTRY_TLS_MIN       6
#define TARGET_GDT_ENTRY_TLS_MAX       (TARGET_GDT_ENTRY_TLS_MIN + TARGET_GDT_ENTRY_TLS_ENTRIES - 1)

#define UNAME_MACHINE "i686"
#define UNAME_MINIMUM_RELEASE "2.6.32"

#define TARGET_CLONE_BACKWARDS
#define TARGET_MINSIGSTKSZ 2048
#define TARGET_MLOCKALL_MCL_CURRENT 1
#define TARGET_MLOCKALL_MCL_FUTURE  2
