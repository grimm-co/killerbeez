#!/bin/sh
# For Windows, this assumes you're using Cygwin, and everything is at C:\killerbeez
# For Linux, this assumes LINUX_BASE_PATH ($HOME/killerbeez/ by default) contains:
#	killerbeez, killerbeez-mutators, killerbeez-utils

if [ -z "$KILLERBEEZ_TEST" ]
then
	echo "Please set KILLERBEEZ_TEST in your environment. Recommended: export KILLERBEEZ_TEST='simple'"
	exit 1
fi

WINDOWS_BASE_PATH="/cygdrive/c/killerbeez/"
WINDOWS_BUILD_PATH=$WINDOWS_BASE_PATH"build/X64/Debug/killerbeez"

LINUX_BASE_PATH="$HOME/killerbeez/"
LINUX_BUILD_PATH="$LINUX_BASE_PATH/build/killerbeez"

FUZZER_WITH_GDB="gdb -q -ex run -ex quit --args ./fuzzer"

# https://stackoverflow.com/a/3466183
unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     machine=Linux;;
    Darwin*)    machine=Mac;;
    CYGWIN*)    machine=Cygwin;;
    MINGW*)     machine=MinGw;;
    *)          machine="UNKNOWN:${unameOut}"
esac

# test is a 32-bit binary that crashes on ABCD via stdin or in a file passed as argv[1].
# hang is a 32-bit binary that hangs.

if [ $machine = "Cygwin" ]
then
	# cygwin permissions are strange, so make sure the executables are executable.
	chmod +x $WINDOWS_BASE_PATH/killerbeez/corpus/test/test.exe
	chmod +x $WINDOWS_BASE_PATH/killerbeez/corpus/hang/hang.exe

	if [ $KILLERBEEZ_TEST = "debug" ]
	then
		cd $WINDOWS_BUILD_PATH

		./fuzzer.exe \
		file debug bit_flip \
		-n 9 \
		-l '{"level":0}' \
		-sf 'C:\killerbeez\Killerbeez\corpus\test\inputs\close.txt' \
		-d '{"timeout":20, "path":"C:\\killerbeez\\Killerbeez\\corpus\\test\\test.exe", "arguments":"@@"}'
	fi

	if [ $KILLERBEEZ_TEST = "simple" ]
	then
		cd $WINDOWS_BUILD_PATH

		./fuzzer.exe \
		file dynamorio radamsa \
		-n 3 \
		-sf 'C:\killerbeez\Killerbeez\corpus\test\inputs\input.txt' \
		\
		-d '{"timeout":20, "path":"C:\\killerbeez\\Killerbeez\\corpus\\test\\test.exe", "arguments":"@@"}' \
		\
		-i '{"per_module_coverage": 1,
			"coverage_modules":["test.exe"],
			"timeout": 2000,
			"client_params":
				"-target_module test.exe -target_offset 0x1000 -nargs 3",
			"fuzz_iterations":1,
			"target_path": "C:\\killerbeez\\Killerbeez\\corpus\\test\\test.exe"}' \
		-l '{"level":0}'
	fi

	if [ $KILLERBEEZ_TEST = "hang" ]
	then
		cd $WINDOWS_BUILD_PATH

		./fuzzer \
		file debug bit_flip \
		-n 1 \
		-l '{"level":0}' \
		-sf 'C:\killerbeez\Killerbeez\corpus\test\inputs\input.txt' \
		-d '{"timeout":3, "path":"C:\\killerbeez\\Killerbeez\\corpus\\hang\\hang.exe", "arguments":"@@"}'
	fi

fi


if [ $machine = "Linux" ]
then
	# cygwin permissions are strange, so make sure the executables are executable.
	chmod +x $LINUX_BASE_PATH/killerbeez/corpus/test/test.exe
	chmod +x $LINUX_BASE_PATH/killerbeez/corpus/hang/hang.exe

	if [ $KILLERBEEZ_TEST = "simple" ]
	then
		cd $LINUX_BUILD_PATH

		$FUZZER_WITH_GDB \
		file none bit_flip \
		-n 9 \
		-sf $HOME'/killerbeez/killerbeez/corpus/test/inputs/close.txt' \
		\
		-d '{"timeout":20, "path":"'$LINUX_BASE_PATH'/killerbeez/corpus/test/test-linux", "arguments":"@@"}' \
		\
		-l '{"level":0}' \
		-m '{"num_bits":1}'
	fi

	if [ $KILLERBEEZ_TEST = "hang" ]
	then
		cd $LINUX_BUILD_PATH

		$FUZZER_WITH_GDB \
		file none bit_flip \
		-n 3 \
		-l '{"level":0}' \
		-sf $HOME'/killerbeez/killerbeez/corpus/test/inputs/input.txt' \
		-d '{"timeout":2, "path":"'$LINUX_BASE_PATH'/killerbeez/corpus/hang/hang-linux", "arguments":"@@"}'
	fi

	if [ $KILLERBEEZ_TEST = "radamsa" ]
	then
		cd $LINUX_BUILD_PATH

		$FUZZER_WITH_GDB \
		file none radamsa \
		-n 3 \
		-l '{"level":0}' \
		-sf $HOME'/killerbeez/killerbeez/corpus/test/inputs/input.txt' \
		-d '{"timeout":20, "path":"'$LINUX_BASE_PATH'/killerbeez/killerbeez/corpus/test/test-linux", "arguments":"@@"}'
	fi

	if [ $KILLERBEEZ_TEST = "stdin" ]
	then
		cd $LINUX_BUILD_PATH

		$FUZZER_WITH_GDB \
		stdin none bit_flip \
		-n 9 \
		-l '{"level":0}' \
		-sf $LINUX_BASE_PATH'/killerbeez/killerbeez/corpus/test/inputs/close.txt' \
		-d '{"timeout":20, "path":"'$LINUX_BASE_PATH'/killerbeez/killerbeez/corpus/test/test-linux"}'
	fi
fi

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

