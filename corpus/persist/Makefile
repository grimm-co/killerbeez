BUILD_DIR=../../../build/killerbeez/
KILLERBEEZ_FLAGS=-L$(BUILD_DIR) -lforkserver -I../../instrumentation/

all: persist persist_hang nopersist deferred deferred_nohook

persist:
	$(CC) -DPERSIST test.c -o persist $(KILLERBEEZ_FLAGS)

persist_hang:
	$(CC) -DPERSIST -DHANG test.c -o persist_hang $(KILLERBEEZ_FLAGS)

nopersist:
	$(CC) test.c -o nopersist

deferred:
	$(CC) -DSLOW_STARTUP test.c -o deferred

deferred_nohook:
	$(CC) -DSLOW_STARTUP -DDEFERRED_NOHOOK test.c -o deferred_nohook $(KILLERBEEZ_FLAGS)

clean:
	rm -f persist persist_hang nopersist deferred deferred_nohook
