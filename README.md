

Important differences w.r.t. a regular Linux system:

  - No signal handling. (But note that QEMU itself needs to handle some of them.)

  - In particular, no `SIGPIPE` (it's probably OK to just ignore it, `write()` knows it can return `EPIPE`).

  - Syscall auto-restart (`EINTR` should never be returned)

  - Syscalls return either 0 or a _positive_ error value.

  - Only `int 0x80` is allowed.

  - `ADDR_NO_RANDOMIZE` and `STICKY_TIMEOUTS` are set.


A `cgc_bytes` field exists in `task_struct`, unclear why (seems to equal the number of bytes handled by the last syscall).



configure
---------

Use either `./cgc_configure_debug` or `./cgc_configure_opt`

(Note that `--disable-werror` should not be necessary, but you may not want to waste time on that.)


