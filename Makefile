# Optional LPATH defines where to find any pre-installed libsecutils and UTA libraries, e.g., /usr/lib
# Optional OPENSSL_DIR defines where to find the OpenSSL installation, defaulting to LPATH/.. if set, else ROOTFS/usr
# Optional OUT_DIR defines where libsecutils, libgencmp, and (optional) libcmp shall be placed, defaulting to LPATH if set, else '.'
# Optional BIN_DIR defines where the CLI application shall be placed unless it is empty. It defaults to '.' if unset.
# All these paths may be absolute or relative to the dir containing this Makefile.
# Optional DEBUG_FLAGS may set to prepend to local CFLAGS and LDFLAGS. Also CFLAGS is passed to build goals.
# By default, the Insta Demo CA ist used for demonstration purposes.

ifeq ($(DEB_BUILD_ARCH),)
    SHELL=bash # bash is needed for supporting extended file name globbing
else # within Debian packaging
    SHELL=LD_PRELOAD= bash
    # LD_PRELOAD= is used to prevent Debian packaging give spurios
    #   ERROR: ld.so: object 'libfakeroot-sysv.so' from LD_PRELOAD
    #   cannot be preloaded (cannot open shared object file): ignored.
    # Unfortunately, cannot do this trick generally because otherwise,
    # multi-line shell commands in rules with '\' will throw weird syntax error
endif

PERL=/usr/bin/perl

# variables ####################################################################

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

VERSION=1.0
# must be kept in sync with latest version in debian/changelog
# PACKAGENAME=libgencmp
# DIRNAME=$(PACKAGENAME)-$(VERSION)

ifeq ($(LPATH),)
    ifeq ($(OUT_DIR),)
        override OUT_DIR = .
    endif
    BIN_DIR ?= .
#   ifneq ($(wildcard $(ROOTFS)/usr/local/include/openssl),)
#       OPENSSL_DIR ?= $(ROOTFS)/usr/local
#   else
        OPENSSL_DIR ?= $(ROOTFS)/usr
#   endif
    SECUTILS_DIR=libsecutils
    SECUTILS_LIB=libsecutils$(DLL)
else
    ifeq ($(OUT_DIR),)
        override OUT_DIR = $(LPATH)
    endif
    BIN_DIR ?= $(LPATH)
    OPENSSL_DIR ?= $(LPATH)/..
    # SECUTILS and SECUTILS_LIB not needed since pre-installed
endif

ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
# $(OPENSSL_DIR) is relative path, assumed relative to ./
    OPENSSL_REVERSE_DIR=../$(OPENSSL_DIR)
else
# $(OPENSSL_DIR) is absolute path
    OPENSSL_REVERSE_DIR=$(OPENSSL_DIR)
endif

ifeq ($(shell echo $(OUT_DIR) | grep "^/"),)
# $(OUT_DIR) is relative path, assumed relative to ./
    ifeq ($(OUT_DIR),.)
        OUT_DIR_REVERSE_DIR=..
    else
        OUT_DIR_REVERSE_DIR=../$(OUT_DIR)
    endif
else
# $(OUT_DIR) is absolute path
    OUT_DIR_REVERSE_DIR=$(OUT_DIR)
endif

override CFLAGS += -DOPENSSL_FUNC=__func__ # workaround for pedantic C compiler
ifneq ($(NDEBUG),)
    DEBUG_FLAGS ?= -O2
    override DEBUG_FLAGS += -DNDEBUG=1
else
    DEBUG_FLAGS ?= -g -O0 -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all # not every compiler(version) supports -Og
endif

ifneq ($(EJBCA_ENABLED),)
    include config/EJBCA.env
else
    include config/empty.env
endif
# optional SET_PROXY variable can be set to override default proxy settings
SET_PROXY ?= no_proxy=localhost,127.0.0.1

# defaults for tests:
OPENSSL ?= openssl$(EXE)

MAKECMDGOALS ?= default
ifneq ($(filter-out doc start stop doc doc_only doc/cmpClient.md doc/cmpClient.1.gz \
    clean clean_this clean_test clean_submodules clean_openssl clean_uta clean_deb,$(MAKECMDGOALS)),)
    OPENSSL_VERSION=$(shell $(MAKE) -s --no-print-directory -f OpenSSL_version.mk LIB=header OPENSSL_DIR="$(OPENSSL_DIR)")
    ifeq ($(OPENSSL_VERSION),)
        $(warning WARNING: cannot determine version of OpenSSL in directory '$(OPENSSL_DIR)', assuming 1.1.1)
        OPENSSL_VERSION=1.1.1
    endif
    $(info detected OpenSSL version $(OPENSSL_VERSION).x)
    ifeq ($(shell expr "$(OPENSSL_VERSION)" \< 1.1),1) # same as comparing == 1.0
        $(info enabling compilation quirks for OpenSSL 1.0.2)
        OSSL_VERSION_QUIRKS+=-Wno-discarded-qualifiers -Wno-unused-parameter
    endif
    ifeq ($(shell expr "$(OPENSSL_VERSION)" \<= 3.2),1)
        $(info enabling compilation with standalone CMP library)
        CMP_STANDALONE=1
    endif
else
    OPENSSL_VERSION=1.1.1 # dummy
endif

ifeq ($(LPATH),)
    LIBCMP_DIR=cmpossl
    ifdef CMP_STANDALONE
        LIBCMP_INC=$(OUT_DIR)/include_cmp # consistent to the default value cmpossl/Makefile
    endif
else
    LIBCMP_DIR=cmpossl # TODO correct?
    ifdef CMP_STANDALONE
        LIBCMP_INC=$(LPATH)/../include
    endif
endif

ifeq ($(shell git help submodule | grep progress),)
    GIT_PROGRESS=
else
    GIT_PROGRESS=--progress
endif

################################################################
# generic CMP Client library and CLI-based client
################################################################

.phony: default build
default: build

ifndef USE_ICV
    export SECUTILS_CONFIG_NO_ICV=-DSECUTILS_CONFIG_NO_ICV
endif
ifdef USE_UTA
    export SECUTILS_USE_UTA=1
endif
ifdef NO_TLS
    export SECUTILS_NO_TLS=1
endif

.phony: submodules
ifeq ($(SECUTILS_DIR),)
submodules:
else
.phony: get_submodules build_submodules clean_submodules
submodules: build_submodules

build_submodules: get_submodules build_secutils build_cmpossl

get_submodules: $(SECUTILS_DIR)/include
ifdef CMP_STANDALONE
get_submodules: $(LIBCMP_DIR)/include
endif

update: update_secutils update_cmpossl
	git fetch
	git rebase
	git submodule update

$(SECUTILS_DIR)/include:
	$(MAKE) update_secutils

$(SECUTILS_LIB):
	build_secutils

.phony: update_secutils build_secutils
update_secutils:
	git submodule update $(GIT_PROGRESS) --init --depth 1 $(SECUTILS_DIR)
build_secutils: # not: update_secutils
	$(MAKE) -s -C $(SECUTILS_DIR) build DEBUG_FLAGS="$(DEBUG_FLAGS)" CFLAGS="$(CFLAGS) $(OSSL_VERSION_QUIRKS) $(SECUTILS_CONFIG_NO_ICV)" OPENSSL_DIR="$(OPENSSL_DIR)" OUT_DIR="$(OUT_DIR_REVERSE_DIR)"

ifdef CMP_STANDALONE
$(LIBCMP_DIR)/include:
	$(MAKE) update_cmpossl
endif

ifdef CMP_STANDALONE
LIBCMP_LIB=libcmp$(DLL)
$(OUT_DIR)/$(LIBCMP_LIB): $(LIBCMP_INC)
	build_cmpossl
endif

.phony: update_cmpossl build_cmpossl
update_cmpossl:
	git submodule update $(GIT_PROGRESS) --init --depth 1 cmpossl
build_cmpossl: # not: update_cmpossl
	@ # the old way to build with CMP was: buildCMPforOpenSSL
ifdef CMP_STANDALONE
	$(MAKE) -s -C $(LIBCMP_DIR) build DEBUG_FLAGS="$(DEBUG_FLAGS)" CFLAGS="$(CFLAGS)" OUT_DIR="$(OUT_DIR_REVERSE_DIR)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif

clean_submodules:
	rm -rf $(SECUTILS_DIR) $(SECUTILS_LIB)*
ifdef CMP_STANDALONE
	rm -rf cmpossl $(OUT_DIR)/$(LIBCMP_LIB)*
endif

endif # eq ($(SECUTILS_DIR),)

.phony: build_prereq build_only build_no_tls
build_prereq: submodules

build: build_prereq build_only
ifdef CMP_STANDALONE
	@export LIBCMP_OPENSSL_VERSION=`$(MAKE) -s --no-print-directory -f OpenSSL_version.mk LIB="$(OUT_DIR)/$(LIBCMP_LIB)"` && \
	if [ "$$LIBCMP_OPENSSL_VERSION" != "$(OPENSSL_VERSION)" ]; then \
	    echo "WARNING: OpenSSL version '$$LIBCMP_OPENSSL_VERSION' used for building libcmp does not match '$(OPENSSL_VERSION)' to be used for building client"; \
	fi
endif

OUTLIB=libgencmp$(DLL)
OUTBIN=cmpClient$(EXE)

build_only:
	@$(MAKE) -f Makefile_src build OUT_DIR="$(OUT_DIR)" BIN_DIR="$(BIN_DIR)" LIB_NAME="$(OUTLIB)" VERSION="$(VERSION)" DEBUG_FLAGS="$(DEBUG_FLAGS)" CFLAGS="$(CFLAGS)" OPENSSL_DIR="$(OPENSSL_DIR)" LIBCMP_INC="$(LIBCMP_INC)" OSSL_VERSION_QUIRKS="$(OSSL_VERSION_QUIRKS)"
	@# CFLAGS="-Idebian/temp/usr/include $(CFLAGS)" LDFLAGS="-Ldebian/temp/usr/lib -Wl,-rpath=debian/temp/usr/lib"

build_no_tls:
	$(MAKE) build DEBUG_FLAGS="$(DEBUG_FLAGS)" CFLAGS="$(CFLAGS)" SECUTILS_NO_TLS=1

.phony: clean_test clean clean_uta clean_this

ifeq ($(LPATH),)
clean_uta:
	$(MAKE) -s -C $(SECUTILS_DIR) clean_uta
endif

clean_test:
	$(MAKE) -f Makefile_tests clean

clean_this: clean_test
	$(MAKE) -s -f Makefile_src clean OUT_DIR="$(OUT_DIR)" BIN_DIR="$(BIN_DIR)" LIB_NAME="$(OUTLIB)" VERSION="$(VERSION)"
	@rm -f doc/$(OUTDOC) doc/cmpClient.md

OUTDOC=cmpClient.1.gz
clean: clean_this clean_deb
ifeq ($(LPATH),)
    ifneq ("$(wildcard $(SECUTILS_DIR))","")
	$(MAKE) -s -C $(SECUTILS_DIR) clean_all OUT_DIR="$(OUT_DIR_REVERSE_DIR)" || true
    endif
    #ifdef CMP_STANDALONE not relevant here
    ifneq ("$(wildcard $(LIBCMP_DIR))","")
	$(MAKE) -s -C $(LIBCMP_DIR) clean OUT_DIR="$(OUT_DIR_REVERSE_DIR)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
    endif
    #endif not relevant here
endif

# get CRLs #####################################################################

creds/crls:
	mkdir $@

get_EJBCA_crls: | creds/crls
ifneq ($(EJBCA_ENABLED),)
	@ # ping >/dev/null $(PINGCOUNTOPT) 1 $(EJBCA_HOST) || echo "cannot reach EJBCA at $(EJBCA_HOST)"; exit 1
	@for CA in $(EJBCA_CDPS); \
	do \
		export ca=`echo $$CA | sed  's/\+//g; s/\.//;'`; \
		wget -nv "$(EJBCA_CDP_URL_PREFIX)$$CA$(EJBCA_CDP_URL_POSTFIX)" -O "creds/crls/EJBCA-$$ca.crl"; \
	done
endif

.phony: get_Insta_crls
get_Insta_crls: | creds/crls
	@ #curl -m 2 -s pki.certificate.fi ...
	$(SET_PROXY) wget -O /dev/null --tries=1 --max-redirect=0 --timeout=2 https://www.insta.fi/ --no-verbose
	@ # | fgrep "301 Moved Permanently" -q || (echo "cannot reach pki.certificate.fi"; exit 1)
	@ #curl -s -o creds/crls/InstaDemoCA.crl ...
	$(SET_PROXY) wget --quiet -O creds/crls/InstaDemoCA.crl "http://pki.certificate.fi:8081/crl-as-der/currentcrl-633.crl?id=633"

# demo #########################################################################

ifneq ($(INSTA),)
    CA_SECTION=Insta
    OCSP_CHECK= #$(OPENSSL) ocsp -url "ldap://www.certificate.fi:389/CN=Insta Demo CA,O=Insta Demo,C=FI?caCertificate" -CAfile creds/trusted/InstaDemoCA.crt -issuer creds/trusted/InstaDemoCA.crt -cert creds/operational.crt
    override EXTRA_OPTS += -path pkix/ -newkeytype rsa:1024
else
    CA_SECTION=EJBCA
    OCSP_CHECK=$(OPENSSL) ocsp -url $(EJBCA_OCSP_URL) \
               -CAfile $(EJBCA_CMP_TRUSTED) -issuer $(EJBCA_CMP_ISSUER) \
               -cert creds/operational.crt
    override EXTRA_OPTS +=
endif

.phony: demo demo_Insta demo_EJBCA
demo: demo_Insta
demo_Insta:
	$(MAKE) run_demo INSTA=1 SLEEP="sleep 1"
# for Insta, sleep 1 helps avoid ERROR: server response error : Code=503,Reason=Service Unavailable
demo_EJBCA:
	$(MAKE) run_demo INSTA= EJBCA_ENABLED=1

CMPCLIENT=$(SET_PROXY) LD_LIBRARY_PATH=. ./$(OUTBIN)
GENERATE_OPERATIONAL=$(OPENSSL) x509 -in creds/operational.crt -x509toreq -signkey creds/operational.pem -out creds/operational.csr -passin pass:12345 2>/dev/null
.phony: run_demo
ifeq ($(INSTA),)
run_demo: build get_EJBCA_crls
else
run_demo: build get_Insta_crls
endif
ifeq ($(EJBCA_ENABLED)$(INSTA),)
	$(warning "### skipping demo since not supported in this environment ###")
else
	@which $(OPENSSL) || (echo "cannot find $(OPENSSL), please install it"; false)
	@/bin/echo -e "\n##### running cmpClient demo #####\n"
	$(CMPCLIENT) imprint -section $(CA_SECTION) $(EXTRA_OPTS)
	@/bin/echo -e "\nValidating own CMP client cert"
    ifeq ($(INSTA),)
	$(CMPCLIENT) validate -section validate -cert $(EJBCA_CMP_CLIENT) -tls_cert "" -own_trusted $(EJBCA_TRUSTED) -untrusted $(EJBCA_UNTRUSTED)
	@/bin/echo -e "\nValidating own TLS client cert"
	$(CMPCLIENT) validate -section validate -tls_cert $(EJBCA_TLS_CLIENT) -tls_trusted $(EJBCA_TRUSTED) -untrusted $(EJBCA_UNTRUSTED)
    else
	$(CMPCLIENT) validate -section Insta -tls_cert "" -cert creds/manufacturer.crt -own_trusted creds/trusted/InstaDemoCA.crt # -no_check_time
    endif
	@echo
	$(CMPCLIENT) bootstrap -section $(CA_SECTION) $(EXTRA_OPTS)
	$(GENERATE_OPERATIONAL)
	$(OPENSSL) x509 -noout -text -in creds/operational.crt
	@echo :
	$(OPENSSL) x509 -noout -text -in creds/operational.crt | sed '/^         [0-9a-f].*/d'
	# @echo
	# $(CMPCLIENT) pkcs10 -section $(CA_SECTION)
	@echo
	$(CMPCLIENT) update -section $(CA_SECTION) $(EXTRA_OPTS)
	@echo :
	$(OCSP_CHECK)
	@echo
	@$(SLEEP)
	$(CMPCLIENT) revoke -section $(CA_SECTION) $(EXTRA_OPTS)
	@echo :
	$(OCSP_CHECK)
    ifneq ($(INSTA),)
	@echo
	@$(SLEEP)
	@$(SLEEP)
	$(CMPCLIENT) genm -section $(CA_SECTION) $(EXTRA_OPTS)
	@echo :
    endif
	@echo -e "\n#### demo finished ####"
	@echo :
endif

# tests ########################################################################

.phony: test_EJBCA-AWS
test_EJBCA-AWS: get_EJBCA_crls
ifeq ($(filter-out EJBCA Simple,$(OPENSSL_CMP_SERVER))$(EJBCA_ENABLED),)
	$(warning "### skipping test_$(OPENSSL_CMP_SERVER) since not supported in this environment ###")
else
	$(SET_PROXY) make test_cli OPENSSL_CMP_SERVER=EJBCA
endif

start_Simple:
	@echo "start SimpleLra"
	@cd SimpleLra && ./RunLra.sh &
	@sleep 2
stop_Simple:
	@PID=`ps aux|grep " jar/SimpleLra.jar TestConfig.xml" | grep -v grep | awk '{ print $$2 }'` && \
	if [ -n "$$PID" ]; then echo "stopping SimpleLra" && kill $$PID; fi

.phony: test_Simple
test_Simple: get_EJBCA_crls test/recipes/80-test_cmp_http_data/Simple
ifneq ($(EJBCA_ENABLED),)
	$(MAKE) start_Simple
    ifeq ($(shell expr "$(OPENSSL_VERSION)" \< 1.1),1) # OpenSSL <1.1 does not support OCSP
	$(warning skipping certstatus aspect since OpenSSL <1.1 does not support OCSP)
	make test_cli OPENSSL_CMP_SERVER=Simple OPENSSL_CMP_ASPECTS="connection verification credentials commands enrollment"
    else
	$(MAKE) -f Makefile_tests test_cli OPENSSL_CMP_SERVER=Simple OPENSSL=$(OPENSSL)
    endif
	$(MAKE) stop_Simple
endif

.phony: test_Insta
test_Insta: get_Insta_crls
	$(SET_PROXY) $(MAKE) -f Makefile_tests test_cli OPENSSL_CMP_SERVER=Insta

.phony: test_profile profile_Simple profile_EJBCA
test_profile: start_Simple profile_Simple profile_EJBCA stop_Simple
# do before: cd SimpleLra && ./RunLra.sh
profile_Simple:
	PROFILE=Simple make profile
profile_EJBCA:
	PROFILE=EJBCA make profile
profile: build
ifeq ($(EJBCA_ENABLED),)
	$(warning "### skipping test_profile since not supported in this environment ###")
else
	@/bin/echo -e "\n##### Requesting a certificate from a PKI with MAC-based protection (RECOMMENDED) #####"
	$(CMPCLIENT) -config config/profile.cnf -section $(PROFILE),EE04
	@/bin/echo -e "\n##### Requesting a certificate from a new PKI with signature-based protection (MANDATORY) #####"
	$(CMPCLIENT) -config config/profile.cnf -section $(PROFILE),EE01
	@/bin/echo -e "\n##### Updating an existing certificate with signature-ased protection (MANDATORY) #####"
	$(CMPCLIENT) -config config/profile.cnf -section $(PROFILE),EE03 -subject ""
	@/bin/echo -e "\n##### Requesting an additional certificate with signature-based protection (OPTIONAL) #####"
	$(CMPCLIENT) -config config/profile.cnf -section $(PROFILE),EE02
#	@/bin/echo -e "\n##### Request a certificate from a legacy PKI using PKCS#10 request (OPTIONAL) #####"
#	$(CMPCLIENT) -config config/profile.cnf -section $(PROFILE),EE05 -subject ""
	@/bin/echo -e "\n##### Revoking a certificate (RECOMMENDED) #####"
	$(CMPCLIENT) -config config/profile.cnf -section $(PROFILE),EE08 -subject ""
	@/bin/echo -e "\n##### Error reporting by client (MANDATORY) #####"
	! $(CMPCLIENT) -config config/profile.cnf -section $(PROFILE),EE09
	@/bin/echo -e "\n##### Error reporting by server (MANDATORY) #####"
	! $(CMPCLIENT) -config config/profile.cnf -section $(PROFILE),RA36
	@echo "\n##### All profile tests succeeded #####"
endif

.phony: all test_all test tests doc doc_only zip
all:	build doc

.phony: test_Mock
test_Mock:
	$(MAKE) -f Makefile_tests test_Mock OUTBIN=$(OUTBIN) OPENSSL=$(OPENSSL)

.phony: tests_LwCmp
tests_LwCmp:
	$(MAKE) -f Makefile_tests tests_LwCmp OUTBIN=$(OUTBIN) OPENSSL=$(OPENSSL)

ifneq ($(EJBCA_ENABLED),)
test_all: demo_EJBCA
endif
test_all: test_profile test test_Mock tests_LwCmp test_Simple test_Insta

test: clean build_no_tls
	@$(MAKE) clean build demo_Insta DEBUG_FLAGS="$(DEBUG_FLAGS)" CFLAGS="$(CFLAGS)"

# doc and zip ##################################################################

doc: doc_only get_submodules
	$(MAKE) -s -C $(SECUTILS_DIR) doc

doc_only: doc/$(OUTDOC) doc/cmpClient.md

%.gz: %
	@which gzip || (echo "cannot find gzip, please install it"; false)
	gzip -f $<

%.1: %.pod
	@which pod2man || (echo "cannot find pod2man, please install perl"; false)
	pod2man --section=1 --center="cmpClient Documentation" --release=$(VERSION) $< >$@

%.md: %.pod
	@which pod2markdown || (echo "cannot find pod2markdown, please install libpod-markdown-perl"; false)
	pod2markdown $< $@

zip:
	zip genCMPClient.zip \
            LICENSE.txt *.md .gitmodules Makefile{,_src} CMakeLists.txt \
	    OpenSSL_version.{c,mk} include/genericCMPClient.h \
	    src/cmpClient.c src/genericCMPClient.c \
	    cmpClient.pod Generic_CMP_client_API.odt


################################################################
# build CMPforOpenSSL (i.e., OpenSSL with CMP patch) with debug symbols
## 'install' static libs to lib, headers to include, dynamic libs and bin to bin
################################################################

ROOTDIR=$(PWD)
TAR=$(SECUTILS_DIR)/tar

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


.phony: deb clean_deb
deb: get_submodules
ifeq ($(LPATH),)
	@# mkdir -p debian/temp
	$(MAKE) deb -C $(SECUTILS_DIR)
	@# dpkg --force-not-root --force-depends --root debian/temp -i libsecutils{,-dev}_*.deb
	sudo dpkg -i libsecutils{,-dev}_*.deb
#ifdef CMP_STANDALONE not relevant here
    ifneq ("$(wildcard $(LIBCMP_DIR))","")
	$(MAKE) deb -C $(LIBCMP_DIR)
	@# dpkg --force-not-root --force-depends --root debian/temp -i libcmp{,-dev}_*.deb
	sudo dpkg -i libcmp{,-dev}_*.deb
    endif
#endif not relevant here
endif
	#pkg-config --print-errors libsecutils
	#pkg-config --print-errors libcmp
	debuild -uc -us --lintian-opts --profile debian # --fail-on none
# alternative:
#	LD_LIBRARY_PATH= dpkg-buildpackage -d -uc -us # may prepend DH_VERBOSE=1
	@# dpkg --contents ../libgencmp{,-dev}_*.deb
	@# dpkg --contents ../cmpclient_*.deb
	sudo dpkg -i ../libgencmp{,-dev}_*.deb ../cmpclient_*.deb

clean_deb:
	rm -rf debian/tmp debian/libgencmp{,-dev} debian/cmpclient
	@# rm -rf debian/temp
	rm -f debian/{files,debhelper-build-stamp} debian/*.{log,substvars}
	rm -f ../libgencmp{_,-}* ../cmpclient*
	@# sudo dpkg -r cmpclient lib{gen,}cmp{,-dev} libsecutils{,-dev}

# installation target - append ROOTFS=<path> to install into virtual root filesystem
DEST_LIB=$(ROOTFS)/usr/lib
DEST_BIN=$(ROOTFS)/usr/bin
DEST_INC=$(ROOTFS)/usr/include
DEST_DOC=$(ROOTFS)/usr/share/man/man1
GENCMPCL_HDRS=genericCMPClient.h
.phony: install install_cli uninstall
install: doc/$(OUTDOC) build # $(OUT_DIR)/$(OUTLIB) $(OUT_DIR)/$(OUTBIN)
	install -D $(OUT_DIR)/$(OUTLIB) $(DEST_LIB)/
	install $(SECUTILS_LIB).* $(DEST_LIB)/
ifdef CMP_STANDALONE
	install $(OUT_DIR)/$(LIBCMP_LIB).* $(DEST_LIB)/
endif
	ln -sf $(OUTLIB) $(DEST_LIB)/$(OUTLIB).$(VERSION)
#install_headers:
	find include -type f -name $(GENCMPCL_HDRS) -exec install -Dm 0644 '{}' '$(ROOTFS)/usr/{}' ';'
#install_bins:
#ifdef CMP_STANDALONE
	install -D $(OUT_DIR)/$(OUTBIN) $(DEST_BIN)/$(OUTBIN)
#endif
#install_doc:
	mkdir -p $(DEST_DOC)
	install -D doc/$(OUTDOC) $(DEST_DOC)

uninstall:
	rm -f $(DEST_LIB)/$(OUTLIB){,.$(VERSION)}
	rm -f $(DEST_LIB)/$(SECUTILS_LIB).*
ifdef CMP_STANDALONE
	rm -f $(DEST_LIB)/$(LIBCMP_LIB).*
endif
	find include -type f -name $(GENCMPCL_HDRS) -exec rm '$(ROOTFS)/usr/{}' ';'
	rm -f $(DEST_BIN)/$(OUTBIN)
	rm -f $(DEST_DOC)/$(OUTDOC)
