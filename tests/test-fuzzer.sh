# works from cygwin bash
# assumes you've installed at C:\killerbeez

cd /cygdrive/c/killerbeez/build/X86/Debug/killerbeez

./fuzzer.exe \
file dynamorio radamsa \
-n 3 \
-sf 'C:\killerbeez\Killerbeez\corpus\test\inputs\input.txt' \
\
-d '{"timeout":20, "path":"C:\\killerbeez\\Killerbeez\\corpus\\test\\test.exe"}' \
\
-i '{"per_module_coverage": 1,
	"coverage_modules":["test.exe"],
	"timeout": 2000,
	"client_params":
		"-target_module test.exe -target_offset 0x1000 -nargs 3",
	"fuzz_iterations":1,
	"target_path": "C:\\killerbeez\\Killerbeez\\corpus\\test\\test.exe"}' \
-l '{"level":0}'

# successful output should look like:

# Mon Jun 11 19:59:28 2018 - INFO     - Logging Started
# Mon Jun 11 19:59:28 2018 - DEBUG    - Fuzzing the 0 iteration
# Mon Jun 11 19:59:28 2018 - DEBUG    - Setting up shm region: afl_shm_ce57db765140e79b_0
# Mon Jun 11 19:59:29 2018 - DEBUG    - Dynamorio Instrumentation got hash 4aad8251 temp 4aad8251 (last hash 00000000)
# Mon Jun 11 19:59:29 2018 - DEBUG    - has_new_bits = 2
# Mon Jun 11 19:59:29 2018 - DEBUG    - Module test.exe has new bits (hash 4aad8251, last hash 00000000)
# Mon Jun 11 19:59:29 2018 - CRITICAL - Found new_paths
# Mon Jun 11 19:59:29 2018 - DEBUG    - Fuzzing the 1 iteration
# Mon Jun 11 19:59:30 2018 - DEBUG    - Dynamorio Instrumentation got hash 5052d8f9 temp 5052d8f9 (last hash 4aad8251)
# Mon Jun 11 19:59:30 2018 - DEBUG    - has_new_bits = 2
# Mon Jun 11 19:59:30 2018 - DEBUG    - Module test.exe has new bits (hash 5052d8f9, last hash 4aad8251)
# Mon Jun 11 19:59:30 2018 - CRITICAL - Found new_paths
# Mon Jun 11 19:59:30 2018 - DEBUG    - Fuzzing the 2 iteration
# Mon Jun 11 19:59:30 2018 - DEBUG    - Dynamorio Instrumentation got hash 4aad8251 temp 4aad8251 (last hash 5052d8f9)
# Mon Jun 11 19:59:30 2018 - DEBUG    - has_new_bits = 0
# Mon Jun 11 19:59:30 2018 - INFO     - Ran 3 iterations in 2 seconds

