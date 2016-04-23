/* Code for loading Linux executables.  Mostly linux kernel code.  */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>

#include "qemu.h"

#define NGROUPS 32

char *magicdump_filename = NULL;

/* ??? This should really be somewhere else.  */
abi_long memcpy_to_target(abi_ulong dest, const void *src,
                          unsigned long len)
{
    void *host_ptr;

    host_ptr = lock_user(VERIFY_WRITE, dest, len, 0);
    if (!host_ptr)
        return -TARGET_EFAULT;
    memcpy(host_ptr, src, len);
    unlock_user(host_ptr, dest, 1);
    return 0;
}

static int prepare_binprm(struct linux_binprm *bprm)
{
    struct stat		st;
    int mode;
    int retval;

    if(fstat(bprm->fd, &st) < 0) {
	return(-errno);
    }

    mode = st.st_mode;
    if(!S_ISREG(mode)) {	/* Must be regular file */
	return(-EACCES);
    }
    if(!(mode & 0111)) {	/* Must have at least one execute bit set */
	return(-EACCES);
    }

    bprm->e_uid = geteuid();
    bprm->e_gid = getegid();

    /* Set-uid? */
    if(mode & S_ISUID) {
    	bprm->e_uid = st.st_uid;
    }

    /* Set-gid? */
    /*
     * If setgid is set but no group execute bit then this
     * is a candidate for mandatory locking, not a setgid
     * executable.
     */
    if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
	bprm->e_gid = st.st_gid;
    }

    retval = read(bprm->fd, bprm->buf, BPRM_BUF_SIZE);
    if (retval < 0) {
	perror("prepare_binprm");
	exit(-1);
    }
    if (retval < BPRM_BUF_SIZE) {
        /* Make sure the rest of the loader won't read garbage.  */
        memset(bprm->buf + retval, 0, BPRM_BUF_SIZE - retval);
    }
    return retval;
}

/* Construct the envp and argv tables on the target stack.  */
abi_ulong loader_build_argptr(int envc, int argc, abi_ulong sp,
                              abi_ulong stringp, int push_ptr)
{
    TaskState *ts = (TaskState *)thread_cpu->opaque;
    int n = sizeof(abi_ulong);
    abi_ulong envp;
    abi_ulong argv;

    sp -= (envc + 1) * n;
    envp = sp;
    sp -= (argc + 1) * n;
    argv = sp;
    if (push_ptr) {
        /* FIXME - handle put_user() failures */
        sp -= n;
        put_user_ual(envp, sp);
        sp -= n;
        put_user_ual(argv, sp);
    }
    sp -= n;
    /* FIXME - handle put_user() failures */
    put_user_ual(argc, sp);
    ts->info->arg_start = stringp;
    while (argc-- > 0) {
        /* FIXME - handle put_user() failures */
        put_user_ual(stringp, argv);
        argv += n;
        stringp += target_strlen(stringp) + 1;
    }
    ts->info->arg_end = stringp;
    /* FIXME - handle put_user() failures */
    put_user_ual(0, argv);
    while (envc-- > 0) {
        /* FIXME - handle put_user() failures */
        put_user_ual(stringp, envp);
        envp += n;
        stringp += target_strlen(stringp) + 1;
    }
    /* FIXME - handle put_user() failures */
    put_user_ual(0, envp);

    return sp;
}

int loader_exec(int fdexec, const char *filename, char **argv, char **envp,
             struct target_pt_regs * regs, struct image_info *infop,
             struct linux_binprm *bprm)
{
    int magic_fd = -1;
    int retval;
    int i;

    bprm->p = 0; // TARGET_PAGE_SIZE*MAX_ARG_PAGES-sizeof(unsigned int);
    //memset(bprm->page, 0, sizeof(bprm->page));
    bprm->fd = fdexec;
    bprm->filename = (char *)filename;

    assert(argv == NULL); assert(envp == NULL);
    bprm->argc = 0;
    bprm->argv = NULL;
    bprm->envc = 0;
    bprm->envp = NULL;

    retval = prepare_binprm(bprm);

    if(retval>=0) {
        if (bprm->buf[0] == 0x7f
                && (bprm->buf[1] == 'E' || bprm->buf[1] == 'C')
                && (bprm->buf[2] == 'L' || bprm->buf[2] == 'G')
                && (bprm->buf[3] == 'F' || bprm->buf[3] == 'C')) {
            retval = load_elf_binary(bprm, infop);
        } else {
            return -ENOEXEC;
        }
    }

    if(retval>=0) {
        abi_ulong error, temp_rand;

        error = target_mmap(CGC_MAGIC_PAGE_ADDR, TARGET_PAGE_SIZE,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                            -1, 0);

        if (error == -1) {
            perror("mmap CGC magic page");
            exit(-1);
        }

        if (magicdump_filename != NULL)
        {
            magic_fd = open(magicdump_filename, O_WRONLY|O_CREAT, 0666);
            if (magic_fd < 0)
                fprintf(stderr, "failed to open file %s for magicdump: %s",
                        magicdump_filename,
                        strerror(errno));
        }

        for(i=0; i < TARGET_PAGE_SIZE / sizeof(abi_ulong); i++)
        {
            temp_rand = rand();
            memcpy_to_target(CGC_MAGIC_PAGE_ADDR+(i*sizeof(abi_ulong)),
                             &temp_rand, sizeof(abi_ulong));
            if (!(magic_fd < 0))
            {
                if (write(magic_fd, &temp_rand, sizeof(abi_ulong)) != sizeof(abi_ulong))
                {
                    fprintf(stderr, "error writing to magicdump file %s", strerror(errno));
                    return -1;
                }
                // TODO: Confirm with Nick that it can be closed. dup2 to a high number otherwise.
                close(magic_fd);
            }
        }

        target_mprotect(CGC_MAGIC_PAGE_ADDR, TARGET_PAGE_SIZE, PROT_READ);
    }

    if(retval>=0) {
        /* success.  Initialize important registers */
        do_init_thread(regs, infop);
        return retval;
    }

    /* Something went wrong, return the inode and free the argument pages*/
    for (i=0 ; i<MAX_ARG_PAGES ; i++) {
        g_free(bprm->page[i]);
    }
    return(retval);
}
