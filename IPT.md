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
forward and can be useful, but there are a few issues must be accommodated.

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
replace the disassembling of instructions. However, obtaining a complete CFG of
real world programs is a hard problem, and becomes especially troublesome when a
target calls a library API with a callback function.

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
maintains a set of hashes which encode the TIP and TNT packets in the execution
trace. As mentioned above, the order of TIP and TNT packets are not always the
same, so each of the two packets are hashed independently. The instruction
pointer address is extracted from the TIP packets and hashed into the trace's
TIP hash, while the TNT bits are extracted from the TNT packets and hashed into
the trace's TNT hash  After the hashes have been generated, a hash table is then
used to lookup these hashes and determine if an execution trace has been seen
before.

This approach has the advantage of not requiring disassembling in order to walk
the execution trace. As such, our IPT packet parser is very fast because it only
analyzes the packets relevant to our fuzzer (TNT and TIP packets). However, this
approach does have the disadvantage of requiring IPT instruction pointer address
filtering, to ensure unnecessary libraries are not also traced. This also helps
reduce the non-determinism in the execution trace, as some libraries do not
always trace exactly the same in each execution.

# Execution Traces vs Basic Block Transitions

As compared to basic block transitions, this implementation may overestimate
which execution traces are consider interesting. For instance, imagine two
executions: run A and run B. If run B's execute trace is a subset of run A's
execution trace, our implementation will report it as being interesting, despite
a basic block transition based instrumentation not reporting it as interesting.

Run B may or may not be interesting depending on the specific code being
executed. For instance, run B doesn't exercise any more code, so it may not be
interesting, however if a bug in the program can only be exercised by not
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

kAFL utilizes Intel PT support to trace execution while fuzzing the Operating
System kernels. Rather than hashing TIP/TNT packets, kAFL utilizes a custom
packet decoder that caches disassembly. Similar to Killerbeez, kAFL also ignores
non-relevant IPT packets.  As described above, the Killerbeez implementation
does not a use a disassembler and thus will be faster than kAFL, but is unable
to obtain the basic block transitions that kAFL can.  kAFL's IPT implementation
is available in the [kAFL repository on github](https://github.com/RUB-SysSec/kAFL/blob/master/QEMU-PT/pt/).

# Example

In order to utilize Killerbeez's IPT instrumentation, your processor and Linux
kernel must support IPT. To check for support, look for the directory
`/sys/devices/intel_pt/`. Additionally, Killerbeez's IPT instrumentation
requires address filtering; the number of address filters supported your system
is available in the `/sys/devices/intel_pt/caps/num_address_ranges` file.

The IPT instrumentation can be used as any other instrumentation module would,
i.e. by specifying "ipt" as the instrumentation type.  Currently, the IPT
instrumentation module does not have any options.  The TNT and TIP hashes are
outputted as DEBUG messages, and can be viewed by increasing the logging level
(with the option `-l "{\"level\":0}"`

An example command utilizing the IPT module usage is shown below.  This example
runs 10 iterations of the test-linux binary, mutates the input with the bit_flip
mutator, and feeds the input over stdin to the target program.  This command
will cause a crash in the test-linux binary on the seventh iteration.
```
./fuzzer stdin ipt bit_flip -d "{\"path\":\"$HOME/killerbeez/corpus/test/test-linux\"}" -n 10 -sf $HOME/killerbeez/corpus/test/inputs/close.txt
```

