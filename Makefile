ifeq ($(OS),Windows_NT)
    EXE=.exe
    DLL=.dll
    LIB=bin
else
    EXE=
    DLL=.so
    LIB=lib
endif

################################################################
# generic CMP Client lib and demo
################################################################

.phony: build clean test all
build:	buildCMPforOpenSSL
	cd securityUtilities && git submodule update --init --recursive
	#cp -a include/operators.h securityUtilities/include/
	SEC_NO_UTA=1 $(MAKE) -C securityUtilities build
	$(MAKE) -C src build

clean:
	$(MAKE) -C securityUtilities clean #libclean
	$(MAKE) -C src clean

test:
	./cmpClientDemo

all:	build test

################################################################
# build CMPforOpenSSL (i.e., OpenSSL with CMP patch) with debug symbols
# 'install' static libs to lib, headers to include, dynamic libs and bin to bin
################################################################

ROOTDIR=$(PWD)
TAR=securityUtilities/tar

unpackCMPforOpenSSL_trigger=stage/openssl-*/Configure
${unpackCMPforOpenSSL_trigger}: $(TAR)/openssl-*tar.gz $(TAR)/openssl-*_cmp-*
	@echo "\n##### preparing to build CMPforOpenSSL ######"
	rm -rf stage/openssl-*
	tar xz -C stage --file=`ls $(TAR)/openssl-*tar.gz`
	@echo "\n###### patching CMP extension into OpenSSL ######"
	cd stage/openssl-*; patch -p1 < `ls ../../$(TAR)/openssl-*_cmp-*`
	touch ${unpackCMPforOpenSSL_trigger}
	@echo "##### finished unpacking CMPforOpenSSL ######\n"

configCMPforOpenSSL_trigger=stage/openssl-*/Makefile
${configCMPforOpenSSL_trigger}: ${unpackCMPforOpenSSL_trigger}
	cd stage/openssl-* && ./config no-rc5 no-mdc2 no-idea no-unit-test --prefix=$(ROOTDIR) --debug enable-crypto-mdebug  # enables reporting memory leaks
	@echo "##### finished configuring CMPforOpenSSL ######\n"

makeCMPforOpenSSL_trigger=stage/openssl-*/*crypto*$(DLL)
${makeCMPforOpenSSL_trigger}: ${configCMPforOpenSSL_trigger}
	cd stage/openssl-* && RC=windres make build_generated depend build_libs_nodep apps/openssl$(EXE) ./tools/c_rehash # this list of targets avoids building needless tests
	@echo "##### finished building CMPforOpenSSL ######\n"

installCMPforOpenSSL_trigger=bin/openssl$(EXE)
${installCMPforOpenSSL_trigger}: ${makeCMPforOpenSSL_trigger}
	cd stage/openssl-* && make install_dev >/dev/null && make install_runtime # this list of targets avoids building needless tests
	@echo "##### finished installing CMPforOpenSSL ######\n"

DIRS=stage lib bin
stage:
	mkdir $(DIRS)

allclean: clean
	rm -Rf $(DIRS)

.phony: buildCMPforOpenSSL
buildCMPforOpenSSL: stage ${installCMPforOpenSSL_trigger}
