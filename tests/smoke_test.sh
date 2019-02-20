#!/bin/bash
if [[ "$1" == "kill" ]]; then
	# Clean out the old
	rm -fR killerbeez
fi

# Check out the new (if needed)
if [[ ! -d killerbeez ]]; then
	git clone https://github.com/grimm-co/killerbeez
fi

function generic_error {
	# $1 = return code
	# $2 = command output
	# $3 = error string
	if [[ $1 -ne 0 ]]; then
		echo "$3"
		echo "Output: $2"
		exit 1
	fi
}
function test_linux_error {
	# $1 = return code
	# $2 = command output
	# $3 = mutator
	# $4 = crashing or non-crashing?
	err="Error running fuzzer with $3 on test-linux ($4)"
	generic_error "$1" "$2" "$err"
}

cd killerbeez
# Compile things
mkdir -p build; cd build; cmake ..; make

# Try running the fuzzer and make sure we have some basic functionality
cd killerbeez

# Run the test-linux program with input which should not cause a crash
echo "AAAA" > test0
echo "Running expected non-crashing test"
output=`./fuzzer file return_code honggfuzz -n 300 -sf test0 \
	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
test_linux_error $? "$output" "honggfuzz" "non-crashing"

# There should not have been anything critical in this run (rc should == 1)
echo "$output" | grep CRITICAL &> /dev/null
x=$?
# test_linux_error expects rc = 0
test_linux_error $((x-1)) "$output" "honggfuzz" "non-crashing"

# There should be a number of iterations done
echo "$output" | grep -i ran.*iterations &> /dev/null
test_linux_error $? "$output" "honggfuzz" "non-crashing"


# Ensure that it can also find crashes, given a reasonable seed
echo "ABC@" > test1
echo "Running expected crashing test"
output=`./fuzzer file return_code honggfuzz -n 300 -sf test1 \
	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
test_linux_error $? "$output" "honggfuzz" "crashing"
echo "$output" | grep CRITICAL &> /dev/null
test_linux_error $? "$output" "honggfuzz" "non-crashing"
echo "$output" | grep -i ran.*iterations &> /dev/null
test_linux_error $? "$output" "honggfuzz" "non-crashing"


function string_not_present {
	needle="$1"
	haystack="$2"
	# rc = 0 means string was not present
	echo "$haystack" | grep "$needle" &> /dev/null
	x=$?  # we expect this to be 1 if not found, we want to return 0
	return $((x-1))  # if the needle is not found, so we subtract 1
}
function string_count {
	needle="$1"
	haystack="$2"
	# prints the number of times the needle was found in the haystack
	echo "$haystack" | grep "$needle" | wc -l
}
function no_warnings_no_errors {
	output="$1"
	mutator="$2"
	#echo "output=$output"
	string_not_present "WARNING" "$output"
	test_linux_error $? "$output" "$mutator" "WARNING"
	string_not_present "FATAL" "$output"
	test_linux_error $? "$output" "$mutator" "FATAL"
	string_not_present "CRITICAL" "$output"
	test_linux_error $? "$output" "$mutator" "CRITICAL"
	string_not_present "Ran 0 iterations" "$output"
	test_linux_error $? "$output" "$mutator" "Ran 0 iterations"
}

function find_llvm_config {
	for name in llvm-config llvm-config-3.8 llvm-config-3.7 llvm-config-3.6 llvm-config-3.5; do
		which $name > /dev/null
		if [ "$?" = "0" ]; then
			echo $name
			return 0
		fi
	done
	generic_error 1 "Could not find llvm-config" "Failed to build afl-clang-fast"
}

#####################################################################################
## AFL Instrumentation Tests ########################################################
#####################################################################################

echo "Running tests - instrumentation - afl - building"

# Build afl-gcc
make -C ../../killerbeez/afl_progs/
generic_error $? "make failed" "Failed to build afl-gcc"

# Build afl-clang-fast
LLVM_CONFIG=$(find_llvm_config)
make -C ../../killerbeez/afl_progs/llvm_mode/ LLVM_CONFIG=$LLVM_CONFIG
generic_error $? "make failed" "Failed to build afl-clang-fast"

# Build afl-qemu-trace
pushd ../../killerbeez/afl_progs/qemu_mode/
./build_qemu_support.sh
generic_error $? "make failed" "Failed to build afl-qemu-trace"
popd

# Build afl test programs
afl_testdir="../../killerbeez/corpus/afl_test/"
make -C $afl_testdir AFL_PATH=../../afl_progs/
generic_error $? "make failed" "Failed to build afl test programs"

# Run the test programs with various different AFL based instrumentations
echo "Running tests - instrumentation - afl - testing"
for test_file in test test32 test-qemu test-fast test-fast-deferred test-fast-persist test-fast-persist-deferred; do
	expected=2
	# Unfortunately the persistence mode tests overly report new paths, so we need to adjust the count for them
	if [ "$test_file" = "test-fast-persist" -o "$test_file" = "test-fast-persist-deferred" ]; then
		expected=3
	fi

	# Build the instrumentation options
	inst_options="-i {"
	if [ "$test_file" = "test-fast-deferred" -o "$test_file" = "test-fast-persist-deferred" ]; then
		inst_options="$inst_options\"deferred_startup\":1"
	fi
	if [ "$test_file" = "test-fast-persist" -o "$test_file" = "test-fast-persist-deferred" ]; then
		if [ "$test_file" = "test-fast-persist-deferred" ]; then
			inst_options="$inst_options,"
		fi
		inst_options="$inst_options\"persistence_max_cnt\":5"
	fi
	if [ "$test_file" = "test-qemu" ]; then
		inst_options="$inst_options\"qemu_mode\":1"
	fi
	inst_options="$inst_options}"

	# Run the test and check the number of new paths found
	output=$(./fuzzer stdin afl bit_flip -n 10 -sf test0 -d "{\"path\":\"$afl_testdir/$test_file\"}" $inst_options)
	test_linux_error $? "$output" bit_flip "AFL instrumentation with $test_file new path test"
	no_warnings_no_errors "$output" bit_flip
	new_path_count=$(string_count "Found new_paths" "$output")
	test $new_path_count -eq $expected
	generic_error $? "AFL new paths test failed" "AFL instrumentation with $test_file failed to detect new paths"

	# Run the test again and make sure it finds a crashing input
	output=$(./fuzzer stdin afl bit_flip -n 100 -sf test1 -d "{\"path\":\"$afl_testdir/$test_file\"}" $inst_options)
	test_linux_error $? "$output" bit_flip "AFL instrumentation with $test_file crash test"
	echo "$output" | grep "Found crashes" > /dev/null
	generic_error $? "AFL crash test failed" "AFL instrumentation with $test_file failed to detect a crash"
done

#####################################################################################
## Return Code Instrumentation Tests ################################################
#####################################################################################

# Test the return_code instrumentation with and without the fork server
echo "Running tests - instrumentation - return_code"
output=$(./fuzzer file return_code nop -n 100 -sf test0 -d '{"path":"corpus/test-linux","arguments":"@@"}')
test_linux_error $? "$output" nop "return_code forkserver test"
no_warnings_no_errors "$output" nop
output=$(./fuzzer stdin return_code bit_flip -n 100 -sf test1 -d '{"path":"corpus/test-linux"}')
test_linux_error $? "$output" bit_flip "return_code forkserver crash test"
echo "$output" | grep "Found crashes" > /dev/null
generic_error $? "return_code forkserver crash test failed" "return_code instrumentation failed to detect a crash"
output=$(./fuzzer file return_code nop -n 100 -sf test0 -d '{"path":"corpus/test-linux","arguments":"@@"}' -i '{"use_fork_server":0}')
test_linux_error $? "$output" nop "return_code no forkserver test"
no_warnings_no_errors "$output" nop
output=$(./fuzzer stdin return_code bit_flip -n 100 -sf test1 -d '{"path":"corpus/test-linux"}' -i '{"use_fork_server":0}')
test_linux_error $? "$output" bit_flip "return_code no forkserver crash test"
echo "$output" | grep "Found crashes" > /dev/null
generic_error $? "return_code no forkserver crash test failed" "return_code instrumentation without the forkserver failed to detect a crash"

#####################################################################################
## Mutator Tests ####################################################################
#####################################################################################

# Now we do more basic tests using other mutators
for mutator in ni bit_flip nop interesting_value havoc arithmetic afl zzuf; do
	echo "Running tests - mutator - $mutator"

	output=$(./fuzzer file return_code $mutator -n 30 -sf test0 -d '{"path":"corpus/test-linux","arguments":"@@"}')
	test_linux_error $? "$output" $mutator "$mutator file basic test"
	no_warnings_no_errors "$output" $mutator

	output=$(./fuzzer stdin return_code $mutator -n 30 -sf test0 -d '{"path":"corpus/test-linux"}')
	test_linux_error $? "$output" $mutator "$mutator stdin basic test"
	no_warnings_no_errors "$output" $mutator
done

# TODO: add tests for multipart, radamsa, dictionary, and splice
#output=`./fuzzer file return_code splice -n 30 -sf test0 \
#	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
#test_linux_error $? "$output" splice "basic test"
#no_warnings_no_errors "$output" splice

# Want to test the no_warnings_no_errors function?  Uncomment
# the blog below to try a made-up mutator
#output=`./fuzzer file return_code thisdoesnotexist -n 30 -sf test0 \
#	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
#test_linux_error $? "$output" thisdoesnotexist "basic test"
#no_warnings_no_errors "$output" thisdoesnotexist

exit 0  # If we got here, we're good

