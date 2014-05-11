-include config.make
-include Makefile.inc

all:
	make -C src
	make -C test

clean:
	make clean -C src
	make clean -C test

