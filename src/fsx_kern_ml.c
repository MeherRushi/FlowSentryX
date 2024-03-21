/*
Since the kernel has the following restrictions :
    (1) limitations on the quantity of eBPF instructions and stack space, 
    (2) prohibitions on unbounded loops, non-static global variables, variadic functions,
        multi-threaded programming, and floating-point representation, and 
    (3) enforcement of array bound checks

Given that all instructions must adhere to integer arithmetic, fixed-point
numbers are employed instead of floating-point numbers within eBPF
programs [39]. The maximum number of instructions within an eBPF
program is restricted to one million BPF instructions with a maximum
of 8192 jump instructions.2 The maximum stack space available for an
eBPF program is limited to 512 bytes [4], a value significantly smaller
than the user space’s default maximum of 8192 KB for stack space.
This constraint indicates that local variables with substantial sizes are
unavailable. These constraints apply per eBPF/XDP program.
*/