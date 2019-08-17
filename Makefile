# optional LPATH defines absolute path where to find pre-installed libraries, e.g., /usr/lib
# optional OPENSSL_DIR defines absolute or relative path to OpenSSL installation
# set INSTA=1 for demo/tests with the Insta Demo CA; use 'make clean_insta' when switching from default to INSTA or vice versa

SHELL=bash # This is needed because of a problem in "build" rule

ifeq ($(OS),Windows_NT)
    EXE=.exe
    DLL=.dll
    OBJ=.obj
#   LIB=bin
    PINGCOUNT=-n
else
    EXE=
    DLL=.so
    OBJ=.o
#   LIB=lib
    PINGCOUNT=-c
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

ifeq ($(findstring clean,$(MAKECMDGOALS)),)
OPENSSL_VERSION=$(shell $(MAKE) -s --no-print-directory -f OpenSSL_version.mk LIB=h OPENSSL_DIR="$(OPENSSL_DIR)")
ifeq ($(OPENSSL_VERSION),)
    $(warning cannot determine version of OpenSSL in directory '$(OPENSSL_DIR)', assuming 1.0.2)
    OPENSSL_VERSION=1.0
endif
$(info detected OpenSSL version $(OPENSSL_VERSION).x)
ifeq ($(shell expr $(OPENSSL_VERSION) \< 1.1),1) # same as comparing == 1.0
    $(info enabling compilation quirks for OpenSSL 1.0.2)
    OSSL_VERSION_QUIRKS+=-Wno-discarded-qualifiers -Wno-unused-parameter
endif
endif


################################################################
# generic CMP Client lib and demo
################################################################

.phony: build clean clean_uta test all zip

ifndef USE_UTA
    export SEC_NO_UTA=1
endif
ifdef NO_TLS
    export SEC_NO_TLS=1
endif

ifdef INSTA
    export CFLAGS += "-DINSTA"
endif

build:
ifeq ($(LPATH),)
	@#git submodule update --init || true
	cd $(SECUTILS) && git submodule update --init
	# cd $(SECUTILS) && git submodule update --init #--recursive || cp --preserve=timestamps ../include/operators.h include/
	$(MAKE) -C $(SECUTILS) build_only OPENSSL_DIR="$(OPENSSL_DIR)"
	@# the old way to build with CMP was: buildCMPforOpenSSL
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp build LIBCMP_INC="../$(LIBCMP_INC)" LIBCMP_OUT="../$(LIBCMP_OUT)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif
	@export LIBCMP_OPENSSL_VERSION=`$(MAKE) -s --no-print-directory -f OpenSSL_version.mk LIB="$(LIBCMP_OUT)/libcmp$(DLL)"` && \
	if [ "$$LIBCMP_OPENSSL_VERSION" != "$(OPENSSL_VERSION)" ]; then \
	    (echo "WARNING: OpenSSL version $$LIBCMP_OPENSSL_VERSION used for building libcmp does not match $(OPENSSL_VERSION) to be used for building client"; true); \
	fi
	$(MAKE) -f Makefile_src build OPENSSL_DIR="$(OPENSSL_DIR)" LIBCMP_INC="$(LIBCMP_INC)" LIBCMP_OUT="$(LIBCMP_OUT)" OSSL_VERSION_QUIRKS="$(OSSL_VERSION_QUIRKS)"

ifeq ($(LPATH),)
clean_uta:
	$(MAKE) -C $(SECUTILS) clean_uta
endif

clean_insta:
	rm -f  src/cmpClientDemo$(OBJ) cmpClientDemo$(EXE)

clean:
ifeq ($(LPATH),)
	$(MAKE) -C $(SECUTILS) clean
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp clean LIBCMP_INC="../$(LIBCMP_INC)"  LIBCMP_OUT="../$(LIBCMP_OUT)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif
	$(MAKE) -f Makefile_src clean
	rm -f creds/new.*

PROXY=http_proxy=http://tsy1.coia.siemens.net:9400 no_proxy=ppki-playground.ct.siemens.com  # = 194.145.60.1
ifeq ($(INSTA),)
	OCSP_CHECK=openssl ocsp -url http://ppki-playground.ct.siemens.com/ejbca/publicweb/status/ocsp -CAfile creds/trusted/PPKIPlaygroundECCRootCAv10.crt -issuer creds/PPKIPlaygroundECCIssuingCAv10.crt -cert creds/new.crt
else
	OCSP_CHECK= #openssl ocsp -url "ldap://www.certificate.fi:389/CN=Insta Demo CA,O=Insta Demo,C=FI?caCertificate" -CAfile creds/trusted/InstaDemoCA.crt -issuer creds/trusted/InstaDemoCA.crt -cert creds/new.crt
endif
test:	build
	@/bin/echo -e "\n##### running cmpClientDemo #####"
	@if [ -z "$$INSTA" ]; then \
		ping >/dev/null $(PINGCOUNT) 1 ppki-playground.ct.siemens.com; \
		for CA in 'Infrastructure+Root+CA+v1.0' 'Infrastructure+Issuing+CA+v1.0' 'ECC+Root+CA+v1.0' 'RSA+Root+CA+v1.0'; \
		do \
			export ca=`echo $$CA | sed  's/\+//g; s/\.//;'`; \
			$(PROXY) wget -q "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+$$CA%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" -O "creds/crls/PPKIPlayground$$ca.crl"; \
		done; \
	else \
		curl -m 2 pki.certificate.fi -s | fgrep "301 Moved Permanently" -q || (echo "cannot reach pki.certificate.fi"; exit 1); \
		$(PROXY) curl -s "http://pki.certificate.fi:8080/crl-as-der/currentcrl-633.crl?id=633" -o "creds/crls/InstaDemoCA.crl"; \
	fi
	$(PROXY) ./cmpClientDemo$(EXE)
	@echo :
	openssl x509 -noout -text -in creds/new.crt | sed '/^         [0-9a-f].*/d'
	@echo
	$(PROXY) ./cmpClientDemo$(EXE) imprint
	@echo
	$(PROXY) ./cmpClientDemo$(EXE) update
	@echo :
	$(OCSP_CHECK)
	@echo
	$(PROXY) ./cmpClientDemo$(EXE) revoke
	@echo :
	$(OCSP_CHECK)

test_insta: build_insta
	INSTA=1 $(MAKE) test

all:	build test

zip:
	zip genCMPClient.zip \
            LICENSE README.md .gitmodules Makefile{,_src} CMakeLists.txt \
	    OpenSSL_version.{c,mk} include/genericCMPClient.h \
	    src/cmpClientDemo.c src/genericCMPClient.c




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
	install -Dm 755 libcmp.so $(ROOTFS)/usr/lib/libcmp.so.0

headers_install:
	find include -type d -exec install -d '$(ROOTFS)/usr/{}' ';'
	find include -type f -name '*.h' -exec install -Dm 0644 '{}' '$(ROOTFS)/usr/{}' ';'

uninstall:
	rm -f $(ROOTFS)/usr/lib/$(OUTBIN)
	find include -type f -name '*.h' -exec rm '$(ROOTFS)/usr/{}' ';'
