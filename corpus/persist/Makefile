BUILD_DIR=../../../build/killerbeez/
KILLERBEEZ_FLAGS=-L$(BUILD_DIR) -lforkserver -I../../instrumentation/

all: persist nopersist deferred deferred_nohook

persist:
	$(CC) -DPERSIST test.c -o persist $(KILLERBEEZ_FLAGS)

nopersist:
	$(CC) test.c -o nopersist

deferred:
	$(CC) -DSLOW_STARTUP test.c -o deferred

deferred_nohook:
	$(CC) -DSLOW_STARTUP -DDEFERRED_NOHOOK test.c -o deferred_nohook $(KILLERBEEZ_FLAGS)

clean:
	rm -f persist nopersist deferred deferred_nohook
