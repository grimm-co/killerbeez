BUILD_DIR=../../../build/killerbeez/

persist:
	$(CC) -DPERSIST test.c -o persist -L$(BUILD_DIR) -lforkserver -I../../instrumentation/

nopersist:
	$(CC) test.c -o nopersist

deferred:
	$(CC) -DSLOW_STARTUP test.c -o deferred

clean:
	rm -f persist nopersist
