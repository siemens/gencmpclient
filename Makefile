# optional LPATH defines absolute path where to find pre-installed libraries, e.g., /usr/lib
# optional OPENSSL_DIR defines absolute or relative path to OpenSSL installation

ifeq ($(OS),Windows_NT)
    EXE=.exe
    DLL=.dll
    OBJ=.obj
#   LIB=bin
else
    EXE=
    DLL=.so
    OBJ=.o
#   LIB=lib
endif

ifeq ($(LPATH),)
    SECUTILS=securityUtilities
    LIBCMP_DIR=cmpossl
    LIBCMP_OUT=.
    LIBCMP_INC=./include_cmp
else
    LIBCMP_OUT=$(LPATH)
    LIBCMP_INC=$(LPATH)/../include
endif

ifeq ($(OPENSSL_DIR),)
    OPENSSL_DIR=$(ROOTFS)/usr
endif
ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
# $(OPENSSL_DIR) is relative path, assumed relative to ./
    OPENSSL_REVERSE_DIR=../$(OPENSSL_DIR)
else
# $(OPENSSL_DIR) is absolute path
    OPENSSL_REVERSE_DIR=$(OPENSSL_DIR)
endif

OPENSSL_VERSION_PAT='s/.*?NUMBER\s+//; s/L.*//'
OPENSSL_VERSION=$(shell fgrep OPENSSL_VERSION_NUMBER $(OPENSSL_DIR)/include/openssl/opensslv.h | sed -r $(OPENSSL_VERSION_PAT))
ifeq ($(findstring 0x,$(OPENSSL_VERSION)),)
    $(error cannot determine version of OpenSSL in directory '$(OPENSSL_DIR)')
endif
$(info detected OpenSSL version $(OPENSSL_VERSION))


################################################################
# generic CMP Client lib and demo
################################################################

.phony: build clean clean_uta test all

ifndef USE_UTA
    export SEC_NO_UTA=1
endif

build:
ifeq ($(LPATH),)
	cd $(SECUTILS) && git submodule update --init --recursive || true
	$(MAKE) -C $(SECUTILS) build OPENSSL_DIR="$(OPENSSL_DIR)" CFLAGS=-DSEC_ENABLE_RSA
	@# the old way to build with CMP was: buildCMPforOpenSSL
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp cmp_lib LIBCMP_INC="../$(LIBCMP_INC)" LIBCMP_OUT="../$(LIBCMP_OUT)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif
	@export LIBCMP_OPENSSL_VERSION=`strings $(LIBCMP_OUT)/libcmp$(DLL) | grep OPENSSL_VERSION_NUMBER | sed -r $(OPENSSL_VERSION_PAT)` && \
	if [ $$LIBCMP_OPENSSL_VERSION != "$(OPENSSL_VERSION)" ]; then \
	    (echo "OpenSSL version $$LIBCMP_OPENSSL_VERSION used for building libcmp does not match $(OPENSSL_VERSION) to be used for building client"; false); \
	fi
	$(MAKE) -C src build OPENSSL_DIR="$(OPENSSL_DIR)" LIBCMP_INC="$(LIBCMP_INC)" LIBCMP_OUT="$(LIBCMP_OUT)"

ifeq ($(LPATH),)
clean_uta:
	$(MAKE) -C $(SECUTILS) clean_uta
endif

clean:
ifeq ($(LPATH),)
	$(MAKE) -C $(SECUTILS) clean
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp cmp_clean LIBCMP_INC="../$(LIBCMP_INC)"  LIBCMP_OUT="../$(LIBCMP_OUT)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif
	$(MAKE) -C src clean
	rm -f certs/new.*

test:	build
	@/bin/echo -e "\n##### running cmpClientDemo #####"
	@wget -q "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+Infrastructure+Issuing+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" -O certs/crls/PPKIPlaygroundInfrastructureIssuingCAv10.crl
	./cmpClientDemo$(EXE)

all:	build test

################################################################
# build CMPforOpenSSL (i.e., OpenSSL with CMP patch) with debug symbols
## 'install' static libs to lib, headers to include, dynamic libs and bin to bin
################################################################

ROOTDIR=$(PWD)
TAR=$(SECUTILS)/tar

unpackCMPforOpenSSL_trigger=openssl/Configure
${unpackCMPforOpenSSL_trigger}: $(TAR)/openssl-*tar.gz $(TAR)/openssl-*_cmp-*
	@echo "\n##### preparing to build CMPforOpenSSL ######"
	rm -rf openssl/*
	cd openssl && tar xz --file=`ls ../$(TAR)/openssl-*tar.gz` && mv openssl-*/* . && rmdir openssl-*
	@echo "\n###### patching CMP extension into OpenSSL ######"
	cd openssl && patch -p1 < `ls ../$(TAR)/openssl-*_cmp-*`
	touch ${unpackCMPforOpenSSL_trigger}
	@echo "##### finished unpacking CMPforOpenSSL ######\n"

configCMPforOpenSSL_trigger=openssl/Makefile
${configCMPforOpenSSL_trigger}: ${unpackCMPforOpenSSL_trigger}
	cd openssl && ./config no-rc5 no-mdc2 no-idea no-unit-test --prefix=$(ROOTDIR) --debug enable-crypto-mdebug  # enables reporting memory leaks
	@echo "##### finished configuring CMPforOpenSSL ######\n"

makeCMPforOpenSSL_trigger=openssl/*crypto*$(DLL)
${makeCMPforOpenSSL_trigger}: ${configCMPforOpenSSL_trigger}
	cd openssl && RC=windres make build_generated depend build_libs_nodep apps/openssl$(EXE) ./tools/c_rehash
	@# the above detailed list of targets avoids building needless tests
	@echo "##### finished building CMPforOpenSSL ######\n"

#installCMPforOpenSSL_trigger=bin/openssl$(EXE)
#${installCMPforOpenSSL_trigger}: ${makeCMPforOpenSSL_trigger}
#	cd openssl && make install_dev >/dev/null && make install_runtime
#	@# the above list of targets avoids building needless tests
#	@echo "##### finished installing CMPforOpenSSL ######\n"

DIRS=openssl #lib bin
openssl:
	mkdir $(DIRS)

.phony: clean_all
clean_all: clean
	rm -Rf $(DIRS)

.phony: buildCMPforOpenSSL
buildCMPforOpenSSL: openssl ${makeCMPforOpenSSL_trigger}




# Target for debian packaging
deb: debian_control.in debian_changelog.in
	HEADER_TARGET=headers_install MAKEFLAGS="-j1 LPATH=/usr/lib/" libs/interfaces/debian/makedeb.sh libgenericcmpclient

debdir: debian_control.in debian_changelog.in
	HEADER_TARGET=headers_install MAKEFLAGS="-j1 LPATH=/usr/lib/" libs/interfaces/debian/makedeb.sh libgenericcmpclient debdironly

# installation target - append ROOTFS=<path> to install into virtual root
# filesystem
install: build
	install -Dm 755 libgencmp$(DLL) $(ROOTFS)/usr/lib/libgencmp$(DLL)

headers_install:
	find include -type d -exec install -d '$(ROOTFS)/usr/{}' ';'
	find include -type f -exec install -Dm 0644 '{}' '$(ROOTFS)/usr/{}' ';'
