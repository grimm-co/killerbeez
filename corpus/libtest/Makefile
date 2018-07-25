all: test libs

test: libs
	$(CC) test.c -o test -ltest1 -ltest2 -L.

libs:
	$(CC) lib1.c -o libtest1.so -shared -fPIC
	$(CC) lib2.c -o libtest2.so -shared -fPIC

clean:
	rm -f test libtest1.so libtest2.so
