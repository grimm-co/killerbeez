# Intel Processor Trace Instrumentation

The Intel Processor Trace (IPT) instrumentation module provides coverage
information for the target program. The IPT instrumentation module utilizes
Intel Processor Trace to quickly obtain a set of hashes that represent the
execution trace of a program. For the moment, IPT instrumentation is only
available on Linux. This document describes the Intel PT instrumentation, how to
use it, and the design decisions that lead to its development.

# Background

Beginning with the 5th generation Intel Processors, Intel introduced Intel
Processor Trace to provide an efficient way to trace the execution of a
processor. In order to reduce the overhead and increase the speed of tracing,
IPT records as little information is possible, while still allowing for an exact
trace of execution to be obtained.

IPT works by recording packets which detail the execution trace in memory. IPT
can be configured to limit packet generation based on the address of the
instruction pointer. This allows tracing of specific executables without
generating unnecessary trace information for any libraries used. Each IPT packet
contains a different type of information relating to the execution trace,
however the only two packets that Killerbeez uses are:

* TNT packets - which contain the results of conditional branches (i.e. jnz, jz,
ja, etc). These packets contain a set of bits which correspond to whether the
last several branches were Taken (T) or Not Taken (NT). Depending on the
processor, IPT may send TNT packets in either the short (maximum 6 TNT bits) or
long (maximum 47 TNT bits) form.

* TIP packets - which contain the results of indirect calls/jumps (i.e. call
rax) and if enabled, the saved instruction pointer of ret instructions.

With a recording of these two packets for an execution trace, software can
utilize a disassembler to obtain the exact control flow of an execution. More
information on IPT is available in Chapter 35 of the Intel Architecture
Software Developer's manual.

# Intel PT and Fuzzing

While great in theory, IPT is not perfect for fuzzing. It is a step
forward and can be useful, but there are a few issues that must be accommodated.

In an ideal implementation, IPT would provide a set of basic block transitions,
such as those obtained in the AFL fuzzer or Killerbeez's DynamoRIO
instrumentation. However, IPT only provides the addresses of indirect
jumps/calls and the results of conditional branches. Thus, any attempt to
obtain basic block transitions must decode the packets, disassemble the traced
executable and libraries, and walk through the execution trace. While IPT's
tracing is very fast and low overhead compared to other instrumentations, the
parsing of these traces can be very slow.

One possible optimization for parsing IPT execution traces, is to obtain a
complete Control Flow Graph (CFG) prior to decoding and utilizing the CFG to
replace the disassembling of instructions. However, statically obtaining a
complete CFG of real world programs is a hard problem, and becomes especially
troublesome when a target calls a library API with a callback function.

Another concern is the asynchronous nature and caching of TIP and TNT packets.
TNT bits can be built up and cached for as long as the processor decides, or may
be sent immediately. Further, the number of TNT bits in a TNT packet is
non-deterministic and can vary between runs when tracing the same program. As
such, the order of TIP packets is irrelevant to the order of the TNT packets.
This prevents parsing approaches which rely on TIP packets to skip to relevant
portions of the execution trace.

# Killerbeez Implementation

To compensate for the previously mentioned issues, Killerbeez's implementation
of IPT-based fuzzing does not attempt to disassemble packets. Rather, Killerbeez
maintains a set of hashes which encode the TIP and TNT data in the execution
trace. As mentioned above, the order of TIP and TNT packets are not always the
same, so each of the two packets are hashed independently. The instruction
pointer address is extracted from the TIP packets and hashed into the trace's
TIP hash, while the TNT bits are extracted from the TNT packets and hashed into
the trace's TNT hash. After the hashes have been generated, a hash table is then
used to lookup these hashes and determine if an execution trace has been seen
before.

This approach has the advantage of not requiring disassembling in order to walk
the execution trace. Additionally, our IPT packet parser is able to ignore
irrelevant packets and only focus on TNT and TIP packets. These characteristics
make the Killerbeez IPT packet parser very fast. However, this approach does
have the disadvantage of requiring IPT instruction pointer address filtering, to
ensure unnecessary libraries are not also traced. This also helps reduce the
non-determinism in the execution trace, as some libraries do not always trace
exactly the same in each execution.

# Execution Traces vs Basic Block Transitions

As compared to basic block transitions, this implementation may overestimate
which execution traces are consider interesting. For instance, imagine two
executions: run A and run B. If run B's execution trace is a subset of run A's
execution trace, our implementation will report it as being interesting, despite
a basic block transition based instrumentation not reporting it as interesting.
Run B may or may not be interesting depending on the specific code being
executed. For instance, run B doesn't exercise any additional code, so it may
not be interesting, however if a bug in the program can only be exercised by not
executing a specific piece of code, or executing it fewer times, run B may be
interesting.

In order to compensate for the differences between execution traces and basic
block transitions, the manager will analyze each interesting input generated by
the fuzzing clients before adding it to the working input set. For instance,
depending on the manager design, it may trace the target program's execution
with the interesting input file using another slower instrumentation that is
able to obtain basic block transitions. With the list of basic block transitions
for this input file, the manager can query the database of previously found
basic block transitions and make a decision on whether the client reported
interesting input file is actually interesting enough to be added to the working
input set.

# Comparison of Implementations

## Honggfuzz

Honggfuzz also utilizes Intel PT support to trace userland targets when fuzzing.
Rather than hashing the TIP/TNT packets, honggfuzz utilizes the instruction
pointers in TIP packets as an index into a bitmap which records previously seen
instruction pointers. While this approach is quick and can avoid disassembling
of the target executable and libraries, it disregards the conditional branch
decisions recorded in the TNT packets. While our implementation will
overestimate interesting files, honggfuzz's implementation underestimates
interesting files and will not report an input file that only changes a
conditional branch in the execution of the target program. Honggfuzz's IPT
implementation is available in the [honggfuzz repository on github](https://github.com/google/honggfuzz/blob/master/linux/pt.c).

## kAFL

kAFL utilizes Intel PT support to trace execution while fuzzing Operating System
kernels. Rather than hashing TIP/TNT packets, kAFL utilizes a custom packet
decoder that caches disassembly. Similar to Killerbeez, kAFL also ignores
non-relevant IPT packets. As described above, the Killerbeez implementation does
not a use a disassembler and thus will be faster than kAFL, but is unable to
obtain the basic block transitions that kAFL can. kAFL's IPT implementation is
available in the [kAFL repository on github](https://github.com/RUB-SysSec/kAFL/blob/master/QEMU-PT/pt/).

# Example

In order to utilize Killerbeez's IPT instrumentation, your processor and Linux
kernel must support IPT. To check for support, look for the directory
`/sys/devices/intel_pt/`. Additionally, Killerbeez's IPT instrumentation
requires address filtering; the number of address filters supported on your
system is available in the `/sys/devices/intel_pt/caps/num_address_ranges` file.

The IPT instrumentation can be used as any other instrumentation module would,
i.e. by specifying the name as the instrumentation type. The TNT and TIP hashes
are output as DEBUG messages, and can be viewed by increasing the logging level
(with the option `-l "{\"level\":0}"`).

An example command illustrating the IPT module's usage is shown below. This
example runs 10 iterations of the test-linux binary, mutates the input with the
bit_flip mutator, and feeds the input over stdin to the target program. This
command will cause a crash in the test-linux binary on the seventh iteration.
The IPT instrumentation tracks the TNT and TIP packets that are generated from
the main test-linux executable.
```
./fuzzer stdin ipt bit_flip -d "{\"path\":\"$HOME/killerbeez/build/killerbeez/corpus/test-linux\"}" -n 10 -sf $HOME/killerbeez/killerbeez/corpus/test/inputs/close.txt
```

If instead of tracking code coverage for the main executable, you wish to track
the coverage of a library, then you can use the `coverage_libraries` option.
This option specifies an array of libraries for the IPT instrumentation module
to track coverage information for. The below command illustrates how to use this
option with the included example program. This command tracks the code coverage
of libtest1.so and libtest2.so.
```
./fuzzer stdin ipt bit_flip -d "{\"path\":\"$HOME/killerbeez/build/killerbeez/corpus/libtest\"}" -n 10 \
  -i "{\"coverage_libraries\":[\"$HOME/killerbeez/build/killerbeez/corpus/libtest1.so\",\"$HOME/killerbeez/build/killerbeez/corpus/libtest2.so\"]}" \
  -sf $HOME/killerbeez/killerbeez/corpus/test/inputs/close.txt
```

# Persistence Mode

The IPT instrumentation module provides the ability to use persistence mode to
increase the speed of fuzzing. Persistence mode involves executing multiple
inputs without restarting the target process. While this approach can be much
quicker, it can cause instabilities in the target process if not setup
properly. The IPT instrumentation module's persistence mode is based off the
persistence mode available in the [LLVM instrumentation included in
AFL](https://github.com/mirrorer/afl/tree/master/llvm_mode). As such, it has
similar advantages and disadvantages.

In the IPT instrumentation module, persistence mode is accomplished by modifying
the source code of the target program to repeatedly call the Killerbeez fork
server library's `killerbeez_loop` function. This function is used to mark the
start and stop of the target process testing a single input. An ideal program
for persistence mode is one that has very little global state, or the state can
easily be reset. The structure of a persistence mode program, is shown below,
where the `KILLERBEEZ_LOOP` macro is used to call the fork server. One thing
to note is that the target process must reread any input data, to ensure it is
running with the newly mutated input each iteration. In order to compile the
instrumented source code, it must include the forkserver.h header file (so that
the `KILLERBEEZ_LOOP` macro is defined) and the linker arguments must be
modified to link against the fork server library. A more complete example
program and Makefile that can be used with IPT persistence mode is available in
the corpus/persist/ directory of this repository.

```
  while(KILLERBEEZ_LOOP()) {
    // Read input data.
    // Call library code to be fuzzed.
    // Reset state.
  }
```

Once a program has been instrumented, persistence mode can be enabled by setting
the IPT instrumentation's `persistence_max_cnt` option. The
`persistence_max_cnt` option defines how many inputs to test in a single process
before restarting the target program. This value can be determined
experimentally, but a good starting value is 1000.

An example command illustrating the IPT module's usage with persistence mode is
shown below. This example runs 5000 iterations of the persist binary, mutates
the input with the afl mutator, and feeds the input over stdin to the target
program. The IPT module will run 1000 iterations per persist process.
```
./fuzzer stdin ipt afl -i "{\"persistence_max_cnt\":1000}" -d "{\"path\":\"$HOME/killerbeez/build/killerbeez/corpus/persist\"}" -n 5000 -sf $HOME/killerbeez/killerbeez/corpus/test/inputs/close.txt
```
For comparison, a non-persistence mode run with a similar binary can be started
with this command:
```
./fuzzer stdin ipt afl -d "{\"path\":\"$HOME/killerbeez/build/killerbeez/corpus/nopersist\"}" -n 5000 -sf $HOME/killerbeez/killerbeez/corpus/test/inputs/close.txt
```

# Deferred Startup Mode

Killerbeez's fork server tries to optimize performance of the target process by
executing the target binary until it reaches the `main` function, and then
forking all new processes from the copy stopped at `main`. This ensures all of
the startup code that is executed prior to the `main` function is only ever run
once. However, if a target process has a large startup cost, fuzzing will still
be slow. In these cases, it is beneficial to use the fork server's deferred
startup mode, to wait until after the process has finished starting up to start
the fork server. Killerbeez's deferred startup mode is based off the deferred
instrumentation mode available in the [LLVM instrumentation included in
AFL](https://github.com/mirrorer/afl/tree/master/llvm_mode). Killerbeez offers
two different techniques for enabling the deferred startup mode. Both techniques
are configured by modifying the configuration in the forkserver_config.h header
file in the instrumentation/ directory of this repository and recompiling
Killerbeez.

## Function Hooking

By default, the Killerbeez fork server uses library injection and function
hooking in order to execute code in a target process. Thus, the Killerbeez
deferred startup mode can be enabled by switching which function is hooked.
This mode has the advantage that it can still hook functions in target programs
when source code is unavailable.

In forkserver_config.h, there are 4 preprocessor macros that control the fork
server's function hooking behavior:
* `DISABLE_HOOKING` - This macro disables function hooking. This macro should be
set to 0 to enable function hooking.
* `USE_LIBC_START_MAIN` - This macro controls whether the default function
(`__libc_start_main`) is hooked or not.  To customize the hooked function, this
must be set to 0.
* `CUSTOM_FUNCTION_NAME` - This macro should contain the name of the function to
hook.  The name should NOT be placed in quotes.
* `RUN_BEFORE_CUSTOM_FUNCTION` - This macro determines whether the fork server
should startup before or after the hooked function is called.  Set it to 0 to
start the fork server after the hooked function returns, or 1 to start the fork
server before the hooked function is called.

The deferred executable in the corpus/persist/ directory is an example of a
target where deferred startup mode is advantageous.  This target calls sleep at
the beginning of the program, which will substantially slowdown fuzzing.
Killerbeez can be instructed to wait to start the fork server until after the
sleep call by modifying forkserver_config.h to set the macros as shown below:
```
#define DISABLE_HOOKING            0
#define USE_LIBC_START_MAIN        0
#define CUSTOM_FUNCTION_NAME       sleep
#define RUN_BEFORE_CUSTOM_FUNCTION 0
```

## Source Code Instrumentation

If source code is available, the target program can be modified to explicitly
start the fork server by calling the `KILLERBEEZ_INIT()` macro at the desired
point in the target program. In order to compile the instrumented source code,
it must include the forkserver.h header file (so that the `KILLERBEEZ_INIT`
macro is defined) and the linker arguments must be modified to link against the
fork server library.

Once the target program's source code is modified, the `DISABLE_HOOKING` macro
in the forkserver_config.h file should be set to 1. This ensures the forkserver
does not also try to hook a function to startup.  The deferred_nohook executable
in the corpus/persist/ directory shows an example of using source code
instrumentation to enable deferred startup mode.

