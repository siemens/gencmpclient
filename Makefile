.phony: build clean test all

build:
	cd securityUtilities && git submodule update --init --recursive
	#cp -a include/operators.h securityUtilities/include/
	$(MAKE) -C securityUtilities build
	$(MAKE) -C src build

clean:
	$(MAKE) -C securityUtilities clean #libclean
	$(MAKE) -C src clean

test:
	./cmpClientDemo

all:	build test
