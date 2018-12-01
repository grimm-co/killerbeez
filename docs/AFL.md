# AFL based Instrumentation

The AFL instrumentation module provides coverage information for the target
program. The AFL instrumentation module utilizes the GCC, LLVM, or QEMU based
instrumentation in order to obtain an AFL-style bitmap of the program
coverage. The AFL instrumentation is only available on Linux; for WinAFL based
instrumentation see the [DynamoRIO documentation](docs/DynamoRIO.md). This
document describes the AFL instrumentation module, how to use it, and the
changes that were made from the original
[AFL implementation](http://lcamtuf.coredump.cx/afl/).

# Background

[AFL](http://lcamtuf.coredump.cx/afl/) is a state-of-the-art fuzzer that can
employ several different types of program instrumentation in order to increase
the efficiency of the fuzzer by utilizing coverage information. As one of the
most popular fuzzers available a large number of developers have contributed
enhancements and additional features. As such, Killerbeez hopes to build off of
these contributions by reusing the instrumentation methods available in AFL. AFL
supports instrumentation of source code through the [GCC](https://gcc.gnu.org/)
and [LLVM](https://llvm.org/) based instrumentation, as well as the binary
instrumentation through the use of a modified version of
[QEMU](https://www.qemu.org/).

# Killerbeez Implementation Differences

### Fork Server Differences

In order to standardize the fork server protocol between the AFL instrumentation
and the [IPT instrumentation](docs/IPT.md), the AFL instrumentation has been
slightly modified. The fork server protocol in Killerbeez is based on 1-byte
commands being sent to the fork server and 4-byte responses returning. Five
commands are supported:
1. `EXIT` - kill any child processes and exit
2. `FORK` - fork a new child, but wait to run the new target executable
3. `RUN`  - Tell the newly forked child to run target executable
4. `FORK_RUN` - fork a new child and run the target executable immediately
5. `GET_STATUS` - Return the status (from `waitpid`) of the last child
The GCC, LLVM, and QEMU instrumentation only implements `EXIT`, `FORK_RUN`, and
`GET_STATUS`, whereas the `LD_PRELOAD` library based fork server used in the
IPT instrumentation implements all 5 commands.

### QEMU Instrumentation Differences

The QEMU instrumentation included in Killerbeez has been patched with a number
of third party patches which fix bugs or add enhancements to it. These patches
are available in
[vanhauser-thc's github repo](https://github.com/vanhauser-thc/afl-patches/).
The following patches have been included:
* `afl-qemu-speed.diff` - Updates QEMU to allow caching, ~3 times speed
improvement. See [abiondo's AFL repo](https://github.com/abiondo/afl) or this
[post](https://abiondo.me/2018/09/21/improving-afl-qemu-mode/) describing the
work for more details.
* `afl-qemu-ppc64.diff` - Updates the AFL QEMU instrumentation to work with
PowerPC
* `afl_qemu_optimize_map.diff` - Optimizes the AFL log function in the QEMU
instrumentation.
* `afl_qemu_optimize_entrypoint.diff` - Fixes entrypoint detection in QEMU
instrumentation on ARM.

# GCC Instrumentation

As Killerbeez's GCC instrumentation is based off of AFL's GCC instrumentation,
the process for instrumenting a target is very similar. As such,
[the original README](https://github.com/mirrorer/afl/blob/master/docs/README#L84)'s
instructions for instrumenting a target may provide helpful information.

First, the `afl-gcc` compiler tool needs to be compiled. This tool can be built
by running the following commands:
```
$ cd afl_progs/
$ make
```
The resulting `afl-gcc` and `afl-g++` tools can then be used in place of the
regular gcc/g++ compilers to instrument any source code compiled. The correct
way to compile the target program may vary depending on the specifics of the
build process, but a nearly-universal approach would be:
```
$ CC=/path/to/killerbeez/afl_progs/afl-gcc ./configure
$ make clean all
```
For C++ programs, you'd would also want to set
`CXX=/path/to/killerbeez/afl_progs/afl-g++`.

Once the target program has been instrumented, it can be fuzzed using the
`fuzzer` program.
```
$ ./fuzzer stdin afl bit_flip -d '{"path":"/path/to/test/program"}' -n 10 -sf /path/to/seed/file
```

# LLVM Instrumentation

As Killerbeez's LLVM instrumentation is based off of AFL's LLVM instrumentation,
the process for instrumenting a target is very similar. As such,
[the LLVM README](https://github.com/mirrorer/afl/blob/master/llvm_mode/README.llvm)'s
instructions for instrumenting a target may provide helpful information.

First, the `afl-clang-fast` compiler tool needs to be compiled. This tool can
be built by running the following commands:
```
$ cd afl_progs/llvm_mode
$ make
```
If `make` cannot find a version of `llvm-config` in `PATH`, you may need to
specify the `LLVM_CONFIG` environment variable. The exact filename of
`llvm-config` will vary based on your specific distribution. For Ubuntu 16.04.5
LTS, the make command should be run as follows:
```
$ make LLVM_CONFIG=llvm-config-3.8
```

The resulting `afl-clang-fast` and `afl-clang-fast++` tools can then be used in
place of the regular clang/clang++ compilers to instrument any source code
compiled. Thus, you can instrument the target in a way similar to the GCC
instrumentation, e.g.:
```
$ CC=/path/to/killerbeez/afl_progs/afl-clang-fast ./configure
$ make clean all
```
For C++ programs, you'd would also want to set
`CXX=/path/to/killerbeez/afl_progs/afl-clang-fast++`.

Once the target program has been instrumented, it can be fuzzed using the
`fuzzer` program.
```
$ ./fuzzer stdin afl bit_flip -d '{"path":"/path/to/test/program"}' -n 10 -sf /path/to/seed/file
```

### Persistence Mode

The LLVM based instrumentation supports persistence mode to further increase the
speed of fuzzing. Persistence mode involves executing multiple inputs without
restarting the target process. While this approach can be much quicker, it can
cause instabilities in the target process if not setup properly. In order for
persistence mode to work, the target must reset its state after each test case.

In LLVM based instrumentation, persistence mode is accomplished by modifying the
source code of the target to call the `__AFL_LOOP()` macro.  This macro is used
to mark the start and stop of the target process testing a single input. An
ideal program for persistence mode is one that has very little global state, or
the state can easily be reset. The structure of a persistence mode program, is
shown below, where the `__AFL_LOOP` macro is used to call the fork server. A
more complete example program and Makefile that can be used with LLVM
persistence mode is available in the corpus/afl_test/ directory of this
repository.

```
  while(__AFL_LOOP()) {
    // Read input data.
    // Call library code to be fuzzed.
    // Reset state.
  }
```

Once a program has been instrumented, persistence mode can be enabled by setting
the AFL instrumentation's `persistence_max_cnt` option. The
`persistence_max_cnt` option defines how many inputs to test in a single process
before restarting the target program. This value can be determined
experimentally, but a good starting value is 1000.  An example `fuzzer` command
that utilizes persistence mode is shown below:
```
$ ./fuzzer stdin afl afl -d '{"path":"/path/to/test/program"}' -n 5000 -sf /path/to/seed/file -i '{"persistence_max_cnt":1000}'
```

### Deferred Startup Mode

The AFL instrumentation fork server tries to optimize performance of the target
process by executing the target binary until it reaches the `main` function, and
then forking all new processes from the copy stopped at `main`. This ensures all
of the startup code that is executed prior to the `main` function is only ever
run once. However, if a target process has a large startup cost, fuzzing will
still be slow. In these cases, it is beneficial to use the fork server's
deferred startup mode, to wait until after the process has finished starting up
to start the fork server.

To enable the deferred startup mode, find a suitable location in the code where
the delayed forking can take place.  Ideally, this location would be after any
startup work is performed but before the actual processing of an input begins.
More information on the process for determining this location is available in
the original AFL's [LLVM instrumentation README](https://github.com/mirrorer/afl/blob/master/llvm_mode/README.llvm#L82).

Once this location is selected, add the following code to indicate to the start
the fork server at this location:
```
  __AFL_INIT();
```
Once this code is added, the target program can be compiled with
`afl-clang-fast` and it can then be used with the `fuzzer`.  To enable the
deferred startup mode, the `deferred_startup` option should be passed to the AFL
instrumentation module's options. An example `fuzzer` command that utilizes
deferred startup mode is shown below:
```
$ ./fuzzer stdin afl afl -d '{"path":"/path/to/test/program"}' -n 5000 -sf /path/to/seed/file -i '{"deferred_startup":1}'
```

# QEMU Instrumentation

If source code is not available or the target cannot be successfully
instrumented via the GCC or LLVM instrumentation described above, AFL's QEMU
instrumentation may be the right approach.  AFL's QEMU instrumentation supports
the ability to perform on-the-fly instrumentation of black-box binaries through
its user space emulation mode.  Additionally, this instrumentation can be used
to fuzz binaries built for a different architecture than the host processor
(i.e. fuzzing an ARM binary on an x86 computer).

Before the QEMU instrumentation can be used, the `afl-qemu-trace` binary must be
built.  The commands below will download the QEMU source code, update the code
to include the instrumentation, and build the `afl-qemu-trace` binary.  For
additional instructions and caveats, see
[README.qemu_mode](afl_progs/qemu_mode/README.qemu).
```
$ cd afl_progs/qemu_mode
$ ./build_qemu_support.sh
```

Once `afl-qemu-trace` is compiled, the target program can be fuzzed with the
`fuzzer`. To enable the QEMU instrumentation, the `qemu_mode` option should be
passed to the AFL instrumentation module's options. An example `fuzzer` command
that utilizes qemu mode is shown below:
```
$ ./fuzzer stdin afl bit_flip -d '{"path":"/path/to/test/program"}' -n 10 -sf /path/to/seed/file -i '{"qemu_mode":1}'
```
If the AFL instrumentation cannot automatically detect the location of the
`afl-qemu-trace` binary, you will need to specify the path to `afl-qemu-trace`
with the `qemu_path` option:
```
$ ./fuzzer stdin afl bit_flip -d '{"path":"/path/to/test/program"}' -n 10 -sf /path/to/seed/file -i '{"qemu_mode":1,"qemu_path":"/path/to/afl-qemu-trace"}'
```
