

all: test test32 test-qemu test-fast test-fast-persist test-fast-persist-hang test-fast-deferred test-fast-persist-deferred

help:
	echo "\n\n This Makefile can be used to compile the example test program with AFL instrumentation.\n" \
	"Use the AFL_PATH environment variable to specify the path to afl-gcc/afl-clang-fast\n" \
	"\n" \
	"Example:\n" \
	"  make AFL_PATH=/path/to/afl/ all" \
	"\n"

check-afl-gcc:
	if [ ! "$(shell sh -c 'ls $(AFL_PATH)/afl-gcc > /dev/null; echo $$?')" = "0" ]; then \
		echo "Bad compiler specified '$(AFL_PATH)'. Please use the AFL_PATH environment variable to specify the path to afl-gcc"; \
		exit 1; \
	fi

check-afl-clang-fast:
	if [ ! "$(shell sh -c 'ls $(AFL_PATH)/afl-clang-fast > /dev/null; echo $$?')" = "0" ]; then \
		echo "Bad compiler specified '$(AFL_PATH)'. Please use the AFL_PATH environment variable to specify the path to afl-clang-fast"; \
		exit 1; \
	fi

test: check-afl-gcc
	$(AFL_PATH)/afl-gcc test.c -o test

test32: check-afl-gcc
	$(AFL_PATH)/afl-gcc test.c -m32 -o test32

test-qemu:
	$(CC) test.c -o test-qemu

test-fast: check-afl-clang-fast
	$(AFL_PATH)/afl-clang-fast test.c -o test-fast

test-fast-persist: check-afl-clang-fast
	$(AFL_PATH)/afl-clang-fast test.c -o test-fast-persist          -DPERSIST

test-fast-persist-hang: check-afl-clang-fast
	$(AFL_PATH)/afl-clang-fast test.c -o test-fast-persist-hang     -DPERSIST -DHANG

test-fast-deferred: check-afl-clang-fast
	$(AFL_PATH)/afl-clang-fast test.c -o test-fast-deferred         -DSLOW_STARTUP -DDEFERRED

test-fast-persist-deferred: check-afl-clang-fast
	$(AFL_PATH)/afl-clang-fast test.c -o test-fast-persist-deferred -DSLOW_STARTUP -DDEFERRED -DPERSIST

clean:
	rm -f test test32 test-qemu test-fast test-fast-persist test-fast-persist-hang test-fast-deferred test-fast-persist-deferred
