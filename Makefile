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

ROOTFS ?= $(DESTDIR)$(prefix)

ifeq ($(LPATH),)
#   ifneq ($(wildcard $(ROOTFS)/usr/local/include/openssl),)
#       OPENSSL_DIR ?= $(ROOTFS)/usr/local
#   else
        OPENSSL_DIR ?= $(ROOTFS)/usr
#   endif
    SECUTILS=securityUtilities
    LIBCMP_DIR=cmpossl
    LIBCMP_OUT=.
    LIBCMP_INC=$(LIBCMP_DIR)/include_cmp
else
    OPENSSL_DIR ?= $(LPATH)/..
    LIBCMP_OUT=$(LPATH)
    LIBCMP_INC=$(LPATH)/../include
endif

ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
# $(OPENSSL_DIR) is relative path, assumed relative to ./
    OPENSSL_REVERSE_DIR=../$(OPENSSL_DIR)
else
# $(OPENSSL_DIR) is absolute path
    OPENSSL_REVERSE_DIR=$(OPENSSL_DIR)
endif

OPENSSL_VERSION_NUMBER_SUBST='s/.*?NUMBER\s+//; s/L.*//'
ifdef OPENSSL_VERSION_FROM_INCLUDE
OPENSSL_VERSION=$(shell fgrep OPENSSL_VERSION_NUMBER $(OPENSSL_DIR)/include/openssl/opensslv.h | sed -r $(OPENSSL_VERSION_NUMBER_SUBST))
else
OPENSSL_VERSION_SUBST='s/.*?\(//; s/\).*//'
OPENSSL_VERSION=$(shell make -f OpenSSL_version.mk -B OPENSSL_DIR=$(OPENSSL_DIR) | grep -E 'OpenSSL .*?\(0x.*?\)' | sed -r $(OPENSSL_VERSION_SUBST))
endif
ifeq ($(findstring 0x,$(OPENSSL_VERSION)),)
    $(error cannot determine version of OpenSSL in directory '$(OPENSSL_DIR)')
endif
$(info detected OpenSSL version $(OPENSSL_VERSION))
ifeq ($(shell test $$(printf "%d" $(OPENSSL_VERSION)) -lt $$(printf "%d" 0x10100000); echo $$?),0)
    $(info enabling compilation quirks for OpenSSL 1.0.2)
    OSSL_VERSION_QUIRKS+=-Wno-discarded-qualifiers -Wno-unused-parameter
endif


################################################################
# generic CMP Client lib and demo
################################################################

.phony: build clean clean_uta test all

ifndef USE_UTA
    export SEC_NO_UTA=1
endif

build:
ifeq ($(LPATH),)
	cd $(SECUTILS) && git submodule update --init --recursive || cp --preserve=timestamps ../include/operators.h include/
	$(MAKE) -C $(SECUTILS) build OPENSSL_DIR="$(OPENSSL_DIR)"
	@# the old way to build with CMP was: buildCMPforOpenSSL
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp build LIBCMP_INC="../$(LIBCMP_INC)" LIBCMP_OUT="../$(LIBCMP_OUT)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif
	@export LIBCMP_OPENSSL_VERSION=`strings $(LIBCMP_OUT)/libcmp$(DLL) | grep OPENSSL_VERSION_NUMBER | sed -r $(OPENSSL_VERSION_NUMBER_SUBST)` && \
	if [ $$LIBCMP_OPENSSL_VERSION != "$(OPENSSL_VERSION)" ]; then \
	    (echo "OpenSSL version $$LIBCMP_OPENSSL_VERSION used for building libcmp does not match $(OPENSSL_VERSION) to be used for building client"; false); \
	fi
	$(MAKE) -C src build OPENSSL_DIR="$(OPENSSL_DIR)" LIBCMP_INC="$(LIBCMP_INC)" LIBCMP_OUT="$(LIBCMP_OUT)" OSSL_VERSION_QUIRKS="$(OSSL_VERSION_QUIRKS)"

ifeq ($(LPATH),)
clean_uta:
	$(MAKE) -C $(SECUTILS) clean_uta
endif

clean:
ifeq ($(LPATH),)
	$(MAKE) -C $(SECUTILS) clean
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp clean LIBCMP_INC="../$(LIBCMP_INC)"  LIBCMP_OUT="../$(LIBCMP_OUT)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif
	$(MAKE) -C src clean
	rm -f certs/new.*

test:	build
	@/bin/echo -e "\n##### running cmpClientDemo #####"
	@no_proxy=ppki-playground.ct.siemens.com wget -q "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+Infrastructure+Issuing+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" -O certs/crls/PPKIPlaygroundInfrastructureIssuingCAv10.crl
	no_proxy=ppki-playground.ct.siemens.com ./cmpClientDemo$(EXE)

test_all: test
	no_proxy=ppki-playground.ct.siemens.com ./cmpClientDemo$(EXE) update
	no_proxy=ppki-playground.ct.siemens.com ./cmpClientDemo$(EXE) revoke

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
OUTBIN=libgencmpcl$(DLL)

#SRCS=Makefile include/genericCMPClient.h src/genericCMPClient.c src/cmpClientDemo.c
#SRCS_TAR=libgencmpcl_0.1.0.orig.tar.gz
.phony: deb deb_clean
deb:
	@# #tar czf $(SRCS_TAR) $(SRCS)
	@# #rm -f  $(OUTBIN) debian/tmp/usr/lib/libgencmpcl.so*
	debuild -uc -us -I* --lintian-opts --profile debian
	rm -r debian/tmp
	@# # rm $(SRCS_TAR)

deb_clean:
	rm ../libgencmpcl*.deb

.phony: debian debiandir
debian: debian_control.in debian_changelog.in
	HEADER_TARGET=headers_install MAKEFLAGS="-j1 LPATH=/usr/lib/" libs/interfaces/debian/makedeb.sh libgencmpcl

debiandir: debian_control.in debian_changelog.in
	HEADER_TARGET=headers_install MAKEFLAGS="-j1 LPATH=/usr/lib/" libs/interfaces/debian/makedeb.sh libgencmpcl debdironly

# installation target - append ROOTFS=<path> to install into virtual root
# filesystem
.phony: install headers_install uninstall
install: $(OUTBIN)
	install -Dm 755 $(OUTBIN) $(ROOTFS)/usr/lib/$(OUTBIN)

headers_install:
	find include -type d -exec install -d '$(ROOTFS)/usr/{}' ';'
	find include -type f -name '*.h' -exec install -Dm 0644 '{}' '$(ROOTFS)/usr/{}' ';'

uninstall:
	rm -f $(ROOTFS)/usr/lib/$(OUTBIN)
	find include -type f -name '*.h' -exec rm '$(ROOTFS)/usr/{}' ';'
