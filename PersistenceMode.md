# DynamoRIO Persistence Mode

The DynamoRIO instrumentation module provides coverage information for the
target program.  This module is largely copied from
[WinAFL](https://github.com/ivanfratric/winafl), and as such has many of the
same advantages and disadvantages.  The DynamoRIO instrumentation module
utilizes persistence mode to greatly increase the speed of fuzzing.  This
document describes how to use persistence mode with the DynamoRIO
instrumentation module.

# Background

Persistence mode involves executing multiple inputs without restarting the
process.  While this approach is much quicker, it can cause instabilities in the
target process.  In the DynamoRIO instrumentation module, persistence mode is
accomplished by selecting a target function to wrap, and re-executing this
function for each input.  The re-execution of this function is done by recording
the program counter, the stack address, and the function parameters, and then
simply setting the registers and arguments back to the original values when the
function finishes.  As you can imagine, this can cause problems with larger
programs that rely on the program's global state.

The target function must be carefully selected to ensure that it rereads the
input to ensure that the new input is processed.  Further, the target function
must also finish in order to ensure that the fuzzer can quickly reset and run a
new input.

# Options

In order to enable persistence mode, several options must be passed to the
DynamoRIO instrumentation.

Arguments:

* `-fuzz_iterations` - The number of fuzz inputs to send to a target before
restarting the target.  Default is 1 iteration (i.e. persistence mode is
disabled).
* `-coverage_modules` - The modules (i.e. libraries or the main executable) that
DynamoRIO should track for coverage information.
* `-per_module_coverage` - Whether each of the tracked modules should be recorded
independently (when the option is set to 1) or whether the same coverage map
should be used for all modules (when set to 0).  The default option is to record
each module in the same map.
* `-client_params` - A string of options that should be passed to the DynamoRIO
plugin. See the description of these arguments below.

In addition to the arguments passed to the instrumentation module, there are a
number of options that can be passed to the DynamoRIO plugin that is executed in
the target process' address space.  These arguments are passed inside the
`-client_params` argument.

* `-target_module` - This option specifies which module the target function to
wrap is in.
* `-target_offset` - This option specifies the address of the target function to
wrap.
* `-target_method` - This option specifies the name of the target function to
wrap.  In order for this option to be able to lookup the name, the function
needs to be exported or the symbols for the target module need to be available.
* `-nargs` - The number of arguments that the target function takes.  This is used
to save and restore the arguments between fuzz iterations.
* `-call_convention` - The target function's calling convention.  The default
calling convention is cdecl on 32-bit x86 platforms and Microsoft x64 for
Visual Studio 64-bit applications. Possible values: fastcall, ms64 for Microsoft
x64 Visual Studio, stdcall for cdecl or stdcall, and thiscall.
* `-no_thread_coverage` - With this option enabled, all threads of the target
program will track coverage.  By default, only the thread that hits the target
function will track coverage.
* `-covtype` - the type of coverage being recorded. Supported options are bb for
basic block coverage or edge for edge coverage.  Edge coverage is the default.
* `-write_log` - A debug option that writes a log file to the current directory
with debug information on the DynamoRIO plugin's status.

In order to run the fuzzer in DynamoRIO's persistence mode, the
`-fuzz_iterations`, `-coverage_modules`, `-target_module`, and either the
`-target_method` or `-target_offset` options all need to be setup with values
specific to the target being fuzzed.

# Example

```
fuzzer.exe file dynamorio afl -n 100 -sf C:\<path to repository>\killerbeez\corpus\test\inputs\close.txt -d "{\"path\":\"C:\\<path to repository>\\killerbeez\\corpus\\test\\test.exe\",\"timeout\":2,\"arguments\":\"@@\"}" -i "{\"timeout\": 3000,\"coverage_modules\":[\"test.exe\"], \"client_params\":\"-target_module test.exe -target_offset 0x1000\",\"fuzz_iterations\":50}" -l "{\"level\":0}"
```

This example fuzzes the include test.exe program for 100 iterations, feeding
input mutated by the AFL mutator.  The instrumentation arguments are specified
so that the DynamoRIO instrumentation module will track coverage of the test.exe
binary.  The instrumentation will wrap the test's function at offset 0x1000,
restarting this function for each input.  It will run 50 iterations of this
function, and then restart the program cleanly for the next iteration.  This
specific example will find a crash in the test program at iteration 7.

