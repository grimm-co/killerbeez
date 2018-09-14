#!/bin/sh
# For Windows, this assumes you're using Cygwin, and everything is at C:\killerbeez
# For Linux, this assumes LINUX_BASE_PATH ($HOME/killerbeez/ by default) contains:
#	killerbeez, killerbeez-mutators, killerbeez-utils

if [ -z "$KILLERBEEZ_TEST" ]
then
	echo "Please set KILLERBEEZ_TEST in your environment. Recommended: export KILLERBEEZ_TEST='simple'"
	exit 1
fi

WINDOWS_BASE_PATH='C:\killerbeez\killerbeez\'
WINDOWS_JSON_ESCAPED_BASE_PATH='C:\\killerbeez\\Killerbeez\\' # JSON uses '\' as an escape.
WINDOWS_CYGWIN_BASE_PATH="/cygdrive/c/killerbeez/"
WINDOWS_BUILD_PATH=$WINDOWS_CYGWIN_BASE_PATH"build/X64/Debug/killerbeez"

LINUX_BASE_PATH="$HOME/killerbeez/"
LINUX_BUILD_PATH="$LINUX_BASE_PATH/build/killerbeez/"

FUZZER="./fuzzer"
FUZZER_WITH_GDB="gdb -q -ex run -ex quit --args ./fuzzer" # Remove -ex quit to stay in gdb after completion.
FUZZER_WITH_LLDB='lldb -o run -- ./fuzzer'

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
	chmod +x $WINDOWS_CYGWIN_BASE_PATH/killerbeez/corpus/test/test.exe
	chmod +x $WINDOWS_CYGWIN_BASE_PATH/killerbeez/corpus/hang/hang.exe

	if [ $KILLERBEEZ_TEST = "debug" ]
	then
		cd $WINDOWS_BUILD_PATH

		./fuzzer.exe \
		file debug bit_flip \
		-n 9 \
		-l '{"level":0}' \
		-sf $WINDOWS_BASE_PATH'corpus\test\inputs\close.txt' \
		-d '{"timeout":20,
			 "path":"'$WINDOWS_JSON_ESCAPED_BASE_PATH'corpus\\test\\test.exe",
			 "arguments":"@@"}'
	fi

	if [ $KILLERBEEZ_TEST = "simple" ]
	then
		cd $WINDOWS_BUILD_PATH

		./fuzzer.exe \
		file dynamorio radamsa \
		-n 3 \
		-sf $WINDOWS_BASE_PATH'\corpus\test\inputs\input.txt' \
		\
		-d '{"timeout":20,
			 "path":"'$WINDOWS_JSON_ESCAPED_BASE_PATH'corpus\\test\\test.exe",
			 "arguments":"@@"}' \
		\
		-i '{"per_module_coverage": 1,
			"coverage_modules":["test.exe"],
			"timeout": 2000,
			"client_params":
				"-target_module test.exe -target_offset 0x1000 -nargs 3",
			"fuzz_iterations":1,
			"target_path":"'$WINDOWS_JSON_ESCAPED_BASE_PATH'corpus\\test\\test.exe"}' \
		-l '{"level":0}'
	fi

	if [ $KILLERBEEZ_TEST = "hang" ]
	then
		cd $WINDOWS_BUILD_PATH

		./fuzzer \
		file debug bit_flip \
		-n 1 \
		-l '{"level":0}' \
		-sf $WINDOWS_BASE_PATH'corpus\test\inputs\input.txt' \
		-d '{"timeout":3,
			 "path":"'$WINDOWS_JSON_ESCAPED_BASE_PATH'corpus\\hang\\hang.exe",
			 "arguments":"@@"}'
	fi

	# Tests a single packet via the server driver. If you're sending multiple
	# packets, consider the manager mutator instead.
	if [ $KILLERBEEZ_TEST = "network_server" ]
	then
		cd $WINDOWS_BUILD_PATH

		./fuzzer \
		network_server debug bit_flip \
		-n 10 \
		-l '{"level":0}' \
		-sf $WINDOWS_BASE_PATH'\corpus\network\close.txt' \
		-d '{"timeout":20,
			"path":"'$WINDOWS_JSON_ESCAPED_BASE_PATH'corpus\\network\\server\\server.exe",
			"ip":"127.0.0.1",
			"port":4444}'
	fi

    if [ $KILLERBEEZ_TEST = "network_client" ]
    then
        cd $WINDOWS_BUILD_PATH

        ./fuzzer \
        network_client debug bit_flip \
        -n 10 \
        -l '{"level":0}' \
        -sf $WINDOWS_BASE_PATH'\corpus\network\close.txt' \
        -d '{"timeout":20,
            "path":"'$WINDOWS_JSON_ESCAPED_BASE_PATH'corpus\\network\\client\\client.exe",
            "ip":"127.0.0.1",
            "port":4444}'

    fi
fi


if [ $machine = "Linux" ] || [ $machine = "Mac" ]
then

	if [ $machine = "Linux" ]
	then
		FUZZER=$FUZZER_WITH_GDB
	fi

	# LLDB interprets commas as some kind of syntax, so they need to be
	# escaped. You'll need to do so manually (in the -d option's json string,
	# usually) if you'd like to use this script w/ LLDB.

	# FUZZER=$FUZZER_WITH_LLDB # uncomment me to use

	if [ $KILLERBEEZ_TEST = "simple" ]
	then
		cd $LINUX_BUILD_PATH

		$FUZZER \
		file return_code bit_flip \
		-n 9 \
		-sf $HOME'/killerbeez/killerbeez/corpus/test/inputs/close.txt' \
		-d '{"timeout":20, "path":"'$LINUX_BUILD_PATH'/corpus/test-linux", "arguments":"@@"}' \
		-l '{"level":0}' \
		-m '{"num_bits":1}'
	fi

	if [ $KILLERBEEZ_TEST = "hang" ]
	then
		cd $LINUX_BUILD_PATH

		$FUZZER \
		file return_code bit_flip \
		-n 3 \
		-l '{"level":0}' \
		-sf $HOME'/killerbeez/killerbeez/corpus/test/inputs/input.txt' \
		-d '{"timeout":2, "path":"'$LINUX_BUILD_PATH'corpus/hang-linux", "arguments":"@@"}'
	fi

	if [ $KILLERBEEZ_TEST = "radamsa" ]
	then
		cd $LINUX_BUILD_PATH

		$FUZZER \
		file return_code radamsa \
		-n 3 \
		-l '{"level":0}' \
		-sf $HOME'/killerbeez/killerbeez/corpus/test/inputs/input.txt' \
		-d '{"timeout":20, "path":"'$LINUX_BUILD_PATH'corpus/test-linux", "arguments":"@@"}'
	fi

	if [ $KILLERBEEZ_TEST = "stdin" ]
	then
		cd $LINUX_BUILD_PATH

		$FUZZER \
		stdin return_code bit_flip \
		-n 9 \
		-l '{"level":0}' \
		-sf $LINUX_BASE_PATH'/killerbeez/corpus/test/inputs/close.txt' \
		-d '{"timeout":20, "path":"'$LINUX_BUILD_PATH'corpus/test-linux"}'
	fi

	# Tests a single packet via the server driver. If you're sending
	# multiple packets, consider the manager mutator instead.
	if [ $KILLERBEEZ_TEST = "network_server" ]
	then
		cd $LINUX_BUILD_PATH

		$FUZZER \
		network_server return_code bit_flip \
		-n 10 \
		-l '{"level":0}' \
		-sf $LINUX_BASE_PATH'/killerbeez/corpus/network/close.txt' \
		-d '{"timeout":20,"path":"'$LINUX_BUILD_PATH'/corpus/server-linux","ip":"127.0.0.1","port":4444}'
	fi

    if [ $KILLERBEEZ_TEST = "network_client" ]
    then
        cd $LINUX_BUILD_PATH

        $FUZZER \
        network_client return_code bit_flip \
        -n 10 \
        -l '{"level":0}' \
        -sf $LINUX_BASE_PATH'/killerbeez/corpus/network/close.txt' \
        -d '{"timeout":20,"path":"'$LINUX_BUILD_PATH'corpus/client-linux","ip":"127.0.0.1","port":4444}'

    fi

	if [ $KILLERBEEZ_TEST = "multipart" ]
	then
		cd $LINUX_BUILD_PATH

		$FUZZER_WITH_GDB \
		network_server return_code manager \
		-n 10 \
		-l '{"level":0}' \
		-m '{"mutators":["bit_flip","bit_flip"]}' \
		-sf $LINUX_BASE_PATH'/killerbeez/corpus/network/multipart.txt' \
		-d '{"timeout":20,"path":"'$LINUX_BUILD_PATH'/corpus/server-linux","ip":"127.0.0.1","port":4444}'
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

