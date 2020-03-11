# optional LPATH defines absolute path where to find pre-installed libraries, e.g., /usr/lib
# optional OPENSSL_DIR defines absolute or relative path to OpenSSL installation
# optional INSTA variable can be set (e.g., to 1) for demo/tests with the Insta Demo CA
# optional INSTA variable can be set to override default proxy settings (for use with INSTA)

SHELL=bash # This is needed because of a problem in "build" rule; good for supporting extended file name globbing
PERL=/usr/bin/perl

ifeq ($(OS),Windows_NT)
    EXE=.exe
    DLL=.dll
    OBJ=.obj
#   LIB=bin
    PINGCOUNTOPT=-n
else
    EXE=
    DLL=.so
    OBJ=.o
#   LIB=lib
    PINGCOUNTOPT=-c
endif

ROOTFS ?= $(DESTDIR)$(prefix)

ifeq ($(LPATH),)
#   ifneq ($(wildcard $(ROOTFS)/usr/local/include/openssl),)
#       OPENSSL_DIR ?= $(ROOTFS)/usr/local
#   else
        OPENSSL_DIR ?= $(ROOTFS)/usr
#   endif
    SECUTILS=securityUtilities
    SECUTILS_LIB=$(SECUTILS)/libSecUtils$(DLL)
    LIBCMP_DIR=cmpossl
    LIBCMP_OUT=.
    LIBCMP_LIB=$(LIBCMP_OUT)/libcmp$(DLL)
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

ifeq ($(shell git help submodule | grep progress),)
    GIT_PROGRESS=
else
    GIT_PROGRESS=--progress
endif

################################################################
# generic CMP Client lib and client
################################################################

.phony: default build
default: build

.phony: test all zip

ifndef USE_UTA
    export SEC_NO_UTA=1
endif
ifdef NO_TLS
    export SEC_NO_TLS=1
endif

.phony: submodules
ifeq ($(SECUTILS),)
submodules:
else
.phony: get_submodules build_submodules clean_submodules
submodules: build_submodules

build_submodules: get_submodules build_cmpossl build_secUtils # $(LIBCMP_LIB) $(SECUTILS_LIB)

get_submodules: $(SECUTILS)/libs/interfaces/include/operators.h $(LIBCMP_INC)

$(SECUTILS)/libs/interfaces/include/operators.h: $(SECUTILS)/include
	cd $(SECUTILS) && git submodule update --init libs/interfaces

$(SECUTILS)/include: update_secUtils

$(SECUTILS_LIB):
	build_secUtils

.phony: build_secUtils update_secUtils
update_secUtils:
	git submodule update $(GIT_PROGRESS) --init $(SECUTILS)
build_secUtils: update_secUtils 
	$(MAKE) -C $(SECUTILS) build_only CFLAGS="$(CFLAGS) -DSEC_CONFIG_NO_ICV" OPENSSL_DIR="$(OPENSSL_DIR)"


$(LIBCMP_INC): update_cmpossl

$(LIBCMP_LIB):
	build_cmpossl

.phony: update_cmpossl build_cmpossl
update_cmpossl:
	git submodule update $(GIT_PROGRESS) --init --depth 1 cmpossl
build_cmpossl: update_cmpossl
	@ # the old way to build with CMP was: buildCMPforOpenSSL
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp build LIBCMP_INC="../$(LIBCMP_INC)" LIBCMP_OUT="../$(LIBCMP_OUT)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"

clean_submodules:
	rm -rf $(SECUTILS) cmpossl $(LIBCMP_LIB)

endif

build: submodules
	@export LIBCMP_OPENSSL_VERSION=`$(MAKE) -s --no-print-directory -f OpenSSL_version.mk LIB="$(LIBCMP_OUT)/libcmp$(DLL)"` && \
	if [ "$$LIBCMP_OPENSSL_VERSION" != "$(OPENSSL_VERSION)" ]; then \
	    (echo "WARNING: OpenSSL version $$LIBCMP_OPENSSL_VERSION used for building libcmp does not match $(OPENSSL_VERSION) to be used for building client"; true); \
	fi
	$(MAKE) -f Makefile_src build OPENSSL_DIR="$(OPENSSL_DIR)" LIBCMP_INC="$(LIBCMP_INC)" LIBCMP_OUT="$(LIBCMP_OUT)" OSSL_VERSION_QUIRKS="$(OSSL_VERSION_QUIRKS)" CFLAGS="$(CFLAGS)" 

.phony: clean_test clean clean_uta clean_all

ifeq ($(LPATH),)
clean_uta:
	$(MAKE) -C $(SECUTILS) clean_uta
endif

clean_test:
	rm -f creds/new.*
	rm -rf creds/crls
	rm -f cmpossl/test/recipes/81-test_cmp_cli_data/*/test.*cert*.pem
	rm -f cmpossl/test/recipes/81-test_cmp_cli_data/SimpleLra

clean:
	$(MAKE) -f Makefile_src clean
	rm -f $(LIBCMP_LIB)

clean_all: clean clean_test
ifeq ($(LPATH),)
	$(MAKE) -C $(SECUTILS) clean || true
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp clean LIBCMP_INC="../$(LIBCMP_INC)"  LIBCMP_OUT="../$(LIBCMP_OUT)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif

#PROXY ?= http_proxy=http://de.coia.siemens.net:9400 no_proxy=ppki-playground.ct.siemens.com # or, e.g., tsy1.coia.siemens.net = 194.145.60.1:9400

ifdef INSTA
    unreachable="cannot reach pki.certificate.fi"
    CA_SECTION=Insta
    OCSP_CHECK= #openssl ocsp -url "ldap://www.certificate.fi:389/CN=Insta Demo CA,O=Insta Demo,C=FI?caCertificate" -CAfile creds/trusted/InstaDemoCA.crt -issuer creds/trusted/InstaDemoCA.crt -cert creds/new.crt
else
    unreachable="cannot reach ppki-playground.ct.siemens.com"
    CA_SECTION=EJBCA
    OCSP_CHECK=openssl ocsp -url http://ppki-playground.ct.siemens.com/ejbca/publicweb/status/ocsp \
               -CAfile creds/trusted/PPKIPlaygroundECCRootCAv10.crt -issuer creds/PPKIPlaygroundECCIssuingCAv10.crt \
               -CAfile creds/trusted/PPKIPlaygroundInfrastructureRootCAv10.crt -issuer creds/PPKIPlaygroundInfrastructureIssuingCAv10.crt \
               -cert creds/new.crt
endif

creds/crls:
	mkdir $@

cmpossl/test/recipes/81-test_cmp_cli_data/SimpleLra:
	cd cmpossl/test/recipes/81-test_cmp_cli_data && \
	ln -s ../../../../test/cmpossl/recipes/81-test_cmp_cli_data/SimpleLra

test: build | creds/crls
	@/bin/echo -e "\n##### running cmpClient Demo #####"
ifndef INSTA
	ping >/dev/null $(PINGCOUNTOPT) 1 ppki-playground.ct.siemens.com
	@ # || echo $(unreachable); exit 1
	@for CA in 'Infrastructure+Root+CA+v1.0' 'Infrastructure+Issuing+CA+v1.0' 'ECC+Root+CA+v1.0' 'RSA+Root+CA+v1.0'; \
	do \
		export ca=`echo $$CA | sed  's/\+//g; s/\.//;'`; \
		wget -q "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+$$CA%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" -O "creds/crls/PPKIPlayground$$ca.crl"; \
	done
else
	@ #curl -m 2 -s pki.certificate.fi ...
	$(PROXY) wget -O /dev/null --tries=1 --max-redirect=0 --timeout=2 https://www.insta.fi/ --no-verbose
	@ # | fgrep "301 Moved Permanently" -q
	@ # || (echo $(unreachable); exit 1)
	@ #curl -s -o creds/crls/InstaDemoCA.crl ...
	@$(PROXY) wget --quiet -O creds/crls/InstaDemoCA.crl "http://pki.certificate.fi:8080/crl-as-der/currentcrl-633.crl"
endif
	$(PROXY) ./cmpClient$(EXE) imprint -section $(CA_SECTION) -cert "" -key ""
	@echo
	$(PROXY) ./cmpClient$(EXE) bootstrap -section $(CA_SECTION) -secret ""
	@echo :
	openssl x509 -noout -text -in creds/new.crt | sed '/^         [0-9a-f].*/d'
	@echo
	$(PROXY) ./cmpClient$(EXE) update -section $(CA_SECTION) -secret "" -subject ""
	@echo :
	$(OCSP_CHECK)
	@echo
	@sleep 1 # for INSTA helps avoid ERROR: server response error : Code=503,Reason=Service Unavailable
	$(PROXY) ./cmpClient$(EXE) revoke -section $(CA_SECTION) -secret "" -subject ""
	@echo :
	$(OCSP_CHECK)

test_insta: build
	INSTA=1 $(MAKE) test

test_cli: build
	@echo -e "\n#### running CLI-based tests #### with CMP_TESTS=$$CMP_TESTS"
	@ :
	( HARNESS_ACTIVE=1 \
	  HARNESS_VERBOSE=$(V) \
	  SRCTOP=cmpossl \
	  BLDTOP=. \
	  BIN_D=. \
	  EXE_EXT= \
	  LD_LIBRARY_PATH=$(BIN_D) \
	  $(PERL) test/cmpossl/recipes/81-test_cmp_cli.t )
	@ :

creds/crls/PPKIPlaygroundInfrastructureIssuingCAv10.crl:
	$(MAKE) test

creds/crls/InstaDemoCA.crl:
	$(MAKE) test_insta

test_SimpleLra: cmpossl/test/recipes/81-test_cmp_cli_data/SimpleLra creds/crls/PPKIPlaygroundInfrastructureIssuingCAv10.crl
	make test_cli CMP_TESTS=SimpleLra
	rm -f test/cmpossl/recipes/81-test_cmp_cli_data/SimpleLra/test.cert.pem

test_Insta: creds/crls/InstaDemoCA.crl
	make test_cli CMP_TESTS=Insta
	rm -f cmpossl/test/recipes/81-test_cmp_cli_data/Insta/test.{cert,extracerts}.pem

all:	build test

doc: doc/cmpClient-cli.md

doc/cmpClient-cli.md: doc/cmpClient-cli.pod
	pod2markdown doc/cmpClient-cli.pod doc/cmpClient-cli.md

zip:
	zip genCMPClient.zip \
            LICENSE README.md .gitmodules Makefile{,_src} CMakeLists.txt \
	    OpenSSL_version.{c,mk} include/genericCMPClient.h \
	    src/cmpClient.c src/genericCMPClient.c




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
	@ # the above detailed list of targets avoids building needless tests
	@echo "##### finished building CMPforOpenSSL ######\n"

#installCMPforOpenSSL_trigger=bin/openssl$(EXE)
#${installCMPforOpenSSL_trigger}: ${makeCMPforOpenSSL_trigger}
#	cd openssl && make install_dev >/dev/null && make install_runtime
#	@ # the above list of targets avoids building needless tests
#	@echo "##### finished installing CMPforOpenSSL ######\n"

DIRS=openssl #lib bin
openssl:
	mkdir $(DIRS)

.phony: clean_openssl
clean_openssl:
	rm -Rf $(DIRS)

.phony: buildCMPforOpenSSL
buildCMPforOpenSSL: openssl ${makeCMPforOpenSSL_trigger}




# Target for debian packaging
OUTBIN=libgencmpcl$(DLL)

#SRCS=Makefile include/genericCMPClient.h src/genericCMPClient.c src/cmpClient.c
#SRCS_TAR=libgencmpcl_0.1.0.orig.tar.gz
.phony: deb deb_clean
deb:
	@ # #tar czf $(SRCS_TAR) $(SRCS)
	@ # #rm -f  $(OUTBIN) debian/tmp/usr/lib/libgencmpcl.so*
	debuild -uc -us -I* --lintian-opts --profile debian
	rm -r debian/tmp
	@ # rm $(SRCS_TAR)

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
