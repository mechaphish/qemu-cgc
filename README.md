

Important differences w.r.t. a regular Linux system:

  - No signal handling. (But note that QEMU itself needs to handle some of them.)

  - In particular, no `SIGPIPE` (it's probably OK to just ignore it, `write()` knows it can return `EPIPE`).

  - Syscall auto-restart (`EINTR` should never be returned)

  - Syscalls return either 0 or a _positive_ error value.

  - Only `int 0x80` is allowed.

  - `ADDR_NO_RANDOMIZE` and `STICKY_TIMEOUTS` are set.


A `cgc_bytes` field exists in `task_struct`, unclear why (seems to equal the number of bytes handled by the last syscall).


Initial state
=============

https://github.com/CyberGrandChallenge/libcgc/blob/master/cgcabi.md


Initial stack
-------------

Pages are auto-allocated, rwx, zeroed.
Maximum size: 8MB

     Initial EIP: 0xbaaaaffc
                  8MB (max)


Guess result:
     0xbaaa b000   INVALID
     0xbaaa afff   first valid dword
               .
     0xbaaa affc   first valid dword

               |
               |     grows downward, as usual
               _
                     8 MB max

     0xb2aab000    last possible valid dword



Flag page
---------

Flag page retrieval [PoV type 2] for (this) CFE:

     any 4 contiguous bytes
       in
     page [ 0x4347C000 .. 0x4347CFFF ]

https://github.com/CyberGrandChallenge/cgc-release-documentation/blob/master/walk-throughs/submitting-a-cb.md



Simple test with the VM's gdb
-----------------------------

maps:

    08048000-08049000 r-xp 00000000 fe:01 107659     /home/vagrant/passacarte
    4347c000-4347d000 r--p 00000000 00:00 0
    baa8b000-baaab000 rwxp 00000000 00:00 0          [stack]

gdb info:

    Breakpoint 1, 0x080480c0 in _start ()
    (gdb) info r
    eax            0x0  0
    ecx            0x4347c000   1128775680
    edx            0x0  0
    ebx            0x0  0
    esp            0xbaaaaffc   0xbaaaaffc
    ebp            0x0  0x0
    esi            0x0  0
    edi            0x0  0
    eip            0x80480c0    0x80480c0 <_start>
    eflags         0x202    [ IF ]
    cs             0x73 115
    ss             0x7b 123
    ds             0x7b 123
    es             0x7b 123
    fs             0x7b 123
    gs             0x7b 123

    (gdb) info float
      R7: Empty   0x00000000000000000000
      R6: Empty   0x00000000000000000000
      R5: Empty   0x00000000000000000000
      R4: Empty   0x00000000000000000000
      R3: Empty   0x00000000000000000000
      R2: Empty   0x00000000000000000000
      R1: Empty   0x00000000000000000000
    =>R0: Empty   0x00000000000000000000

    Status Word:         0x0000
                           TOP: 0
    Control Word:        0x037f   IM DM ZM OM UM PM
                           PC: Extended Precision (64-bits)
                           RC: Round to nearest
    Tag Word:            0xffff
    Instruction Pointer: 0x00:0x00000000
    Operand Pointer:     0x00:0x00000000
    Opcode:              0x0000


    (gdb) p *((unsigned char*) 0xbaaab000)
    Cannot access memory at address 0xbaaab000

    (gdb) x/x $esp
    0xbaaaaffc: 0x00000000


BUT: `p *(unsigned char*)0xba2aa000`
Causes a kernel panic!

    kernel BUG at mm/memory.c:1838!
    invalid opcode: 0000 [#2] SMP
    Modules linked in: fbcon bitblit softcursor font qxl drm_kms_helper ttm drm i2c_core fb fbdev virtio_blk virtio_net virtio_pci virtio_ring virtio
    CPU: 0 PID: 3193 Comm: gdb Tainted: G      D       3.13.11-ckt21+ #3
    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Ubuntu-1.8.2-1ubuntu1 04/01/2014
    task: c743ccb0 ti: c69a0000 task.ti: c69a0000
    EIP: 0060:[<c10af1f9>] EFLAGS: 00010246 CPU: 0
    EIP is at __get_user_pages.part.12+0x429/0x430
    EAX: 00000040 EBX: 00000016 ECX: c76c4d40 EDX: 00000000
    ESI: c7655880 EDI: c6b4ad70 EBP: ba2aa000 ESP: c69a1dbc
     DS: 007b ES: 007b FS: 00d8 GS: 0033 SS: 0068
    CR0: 8005003b CR2: 082dc530 CR3: 06806000 CR4: 000007f0
    Stack:
     c64583c0 00000010 c743ccb0 00000000 00000296 cac74000 c6efbc00 cac74034
     00000296 00000000 c64583c0 00000004 ba2aa000 c69a1e74 c10af378 00000001
     00000016 c69a1e24 c69a1e20 00000000 c1097071 c64583c0 c6b4ad70 00000016
    Call Trace:
     [<c10af378>] ? __access_remote_vm+0xb8/0x160
     [<c1097071>] ? get_page_from_freelist+0x431/0x540
     [<c10af6a9>] ? access_process_vm+0x29/0x50
     [<c103de0f>] ? ptrace_request+0x49f/0x6d0
     [<c10ab229>] ? __do_fault+0x419/0x5d0
     [<c10ae4dd>] ? handle_mm_fault+0x11d/0xa10
     [<c100b070>] ? arch_ptrace+0x320/0x4b0
     [<c102dec3>] ? __do_page_fault+0x163/0x460
     [<c102df96>] ? __do_page_fault+0x236/0x460
     [<c1053f9a>] ? task_rq_lock+0x3a/0x70
     [<c1055892>] ? wait_task_inactive+0x72/0xe0
     [<c103e24b>] ? SyS_ptrace+0x20b/0x580
     [<c138ba0c>] ? default_syscall+0x12/0x12
    Code: e0 05 03 05 e4 c2 54 c1 89 c2 e9 58 ff ff ff 89 d0 89 54 24 20 e8 08 b7 fe ff 8b 54 24 20 84 c0 0f 85 8a fd ff ff e9 52 ff ff ff <0f> 0b 90 8d 74 26 00 55 57 56 53 83 ec 04 8b 74 24 1c 8b 5c 24
    EIP: [<c10af1f9>] __get_user_pages.part.12+0x429/0x430 SS:ESP 0068:c69a1dbc



configure
=========

Use either `./cgc_configure_debug` or `./cgc_configure_opt`

(Note that `--disable-werror` should not be necessary, but you may not want to waste time on that.)

