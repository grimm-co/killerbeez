#!/bin/bash
if [[ "$1" == "kill" ]]; then
	# Clean out the old
	rm -fR killerbeez killerbeez-mutators killerbeez-utils build
fi

# Check out the new (if needed)
if [[ ! -d killerbeez-utils ]]; then
	git clone https://github.com/grimm-co/killerbeez-utils
fi
if [[ ! -d killerbeez-mutators ]]; then
	git clone https://github.com/grimm-co/killerbeez-mutators
fi
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

# Compile things
mkdir build; cd build; cmake ../killerbeez; make
#cd build

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

# Now we do more basic tests using other mutators
echo "Running mutator tests"
# TODO: put the mutators which are identical in a loop
output=`./fuzzer file return_code ni -n 30 -sf test0 \
	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
test_linux_error $? "$output" ni "basic test"
no_warnings_no_errors "$output" ni

output=`./fuzzer file return_code bit_flip -n 30 -sf test0 \
	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
test_linux_error $? "$output" bit_flip "basic test"
no_warnings_no_errors "$output" bit_flip

output=`./fuzzer file return_code nop -n 30 -sf test0 \
	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
test_linux_error $? "$output" nop "basic test"
no_warnings_no_errors "$output" nop

output=`./fuzzer file return_code interesting_value -n 30 -sf test0 \
	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
test_linux_error $? "$output" interesting_value "basic test"
no_warnings_no_errors "$output" interesting_value

output=`./fuzzer file return_code havoc -n 30 -sf test0 \
	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
test_linux_error $? "$output" havoc "basic test"
no_warnings_no_errors "$output" havoc

output=`./fuzzer file return_code arithmetic -n 30 -sf test0 \
	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
test_linux_error $? "$output" arithmetic "basic test"
no_warnings_no_errors "$output" arithmetic

output=`./fuzzer file return_code afl -n 30 -sf test0 \
	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
test_linux_error $? "$output" afl "basic test"
no_warnings_no_errors "$output" afl

output=`./fuzzer file return_code zzuf -n 30 -sf test0 \
	-d '{"path":"corpus/test-linux","arguments":"@@"}'`
test_linux_error $? "$output" zzuf "basic test"
no_warnings_no_errors "$output" zzuf

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
