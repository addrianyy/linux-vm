# Linux emulation on Windows
This project emulates Linux syscalls allowing Linux applications to run on Windows.
Currently very few syscalls are handled so it will work only on the most basic applications.
As dynamic libraries are not supported I suggest compiling Linux code with musl standard library.
It requires Windows Hypervisor Platform to run, so you need to install it beforehand.

# Supported syscalls
Some syscalls below are only partially implemented.

* read
* write
* open
* close
* mmap
* munmap
* brk
* ioctl
* readv
* writev
* madvise
* nanosleep
* exit
* creat
* arch_prctl
* set_tid_address
* clock_gettime
* exit_group

# Additional features
Syscall frequencies can be counted when running application. Generating
code coverage file which can be consumed by Lighthouse or other similar tools is also supported.

# Examples
2 simple programs written in C are in examples/ directory. They need to be used
with musl standard library and successfuly run on emulator.
They can be compiled with following command:
<br>
<code>musl-gcc -static app.c -o compiled-app.o</code>
