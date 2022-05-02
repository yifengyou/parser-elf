all:
	gcc -shared -fPIC -Wl,-soname=libfoo.so foo.c -o libfoo.so
	gcc bar.c -o bar -L`pwd` -lfoo

run:
	LD_PRELOAD=`pwd`/libfoo.so ./bar

clean:
	rm -rf bar libfoo.so
