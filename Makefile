# Optional LPATH defines where to find any pre-installed libsecutils and UTA libraries, e.g., /usr/lib
# Optional OPENSSL_DIR defines where to find the OpenSSL installation, defaulting to LPATH/.. if set, else ROOTFS/usr
# Optional OUT_DIR defines where libgencmpcl, libcmp, and libsecutils shall be placed, defaulting to LPATH if set, else '.'
# All these paths may be absolute or relative to the dir containing this Makefile.
# Optional DEBUG_FLAGS may set to prepend to local CFLAGS and LDFLAGS. Also CFLAGS is passed to build goals.
# By default, the Insta Demo CA ist used for demonstration purposes.

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
    ifeq ($(OUT_DIR),)
        override OUT_DIR = .
    endif
#   ifneq ($(wildcard $(ROOTFS)/usr/local/include/openssl),)
#       OPENSSL_DIR ?= $(ROOTFS)/usr/local
#   else
        OPENSSL_DIR ?= $(ROOTFS)/usr
#   endif
    SECUTILS_DIR=libsecutils
    SECUTILS_LIB=$(SECUTILS_DIR)/libsecutils$(DLL)
else
    ifeq ($(OUT_DIR),)
        override OUT_DIR = $(LPATH)
    endif
    OPENSSL_DIR ?= $(LPATH)/..
    # SECUTILS and SECUTILS_LIB not needed since pre-installed
endif
LIBCMP_LIB=$(OUT_DIR)/libcmp$(DLL)

OUTBIN=$(OUT_DIR)/libgencmpcl$(DLL)

ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
# $(OPENSSL_DIR) is relative path, assumed relative to ./
    OPENSSL_REVERSE_DIR=../$(OPENSSL_DIR)
else
# $(OPENSSL_DIR) is absolute path
    OPENSSL_REVERSE_DIR=$(OPENSSL_DIR)
endif

ifeq ($(shell echo $(OUT_DIR) | grep "^/"),)
# $(OUT_DIR) is relative path, assumed relative to ./
    OUT_DIR_REVERSE_DIR=../$(OUT_DIR)
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

ifeq ($(EJBCA_ENABLED),)
EJBCA_ENV= \
	EJBCA_HOST= \
	EJBCA_OCSP_URL= \
	EJBCA_CDP_URL_PREFIX= \
	EJBCA_CDPS= \
	EJBCA_CDP_URL_POSTFIX= \
	EJBCA_CMP_ISSUER= \
	EJBCA_CMP_CLIENT= \
	EJBCA_TLS_CLIENT= \
	EJBCA_CMP_TRUSTED= \
	EJBCA_TRUSTED= \
	EJBCA_UNTRUSTED= \
	EJBCA_CMP_RECIPIENT= \
	EJBCA_CMP_SERVER= \
	EJBCA_CMP_SUBJECT= \
	EJBCA_CMP_SUBJECT_ECC= \
	EJBCA_ENABLED=
endif
ifneq ($(EJBCA_ENABLED),)
# optional SET_PROXY variable can be set to override default proxy settings (for use with INSTA)
    SET_PROXY ?= no_proxy=localhost,127.0.0.1,$$EJBCA_HOST
else
    SET_PROXY ?= no_proxy=localhost,127.0.0.1
endif

# defaults for test_conformance:
LIGHTWEIGHTCMPRA ?= ./LightweightCmpRa.jar
CMPCAMOCK =? ./CmpCaMock.jar
OPENSSL_LIB_PATH ?=
OPENSSL ?= openssl

MAKECMDGOALS ?= default
ifneq ($(filter-out doc clean clean_this clean_test clean_submodules clean_openssl clean_uta clean_deb,$(MAKECMDGOALS)),)
    OPENSSL_VERSION=$(shell $(MAKE) -s --no-print-directory -f OpenSSL_version.mk LIB=header OPENSSL_DIR="$(OPENSSL_DIR)")
    ifeq ($(OPENSSL_VERSION),)
        $(warning cannot determine version of OpenSSL in directory '$(OPENSSL_DIR)', assuming 1.1.1)
        OPENSSL_VERSION=1.1.1
    endif
    $(info detected OpenSSL version $(OPENSSL_VERSION).x)
    ifeq ($(shell expr $(OPENSSL_VERSION) \< 1.1),1) # same as comparing == 1.0
        $(info enabling compilation quirks for OpenSSL 1.0.2)
        OSSL_VERSION_QUIRKS+=-Wno-discarded-qualifiers -Wno-unused-parameter
    endif
    ifeq ($(shell expr $(OPENSSL_VERSION) \< 3.0),1)
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
# generic CMP Client lib and client
################################################################

.phony: default build build_no_tls build_prereq
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

build_submodules: get_submodules build_cmpossl build_secutils # $(LIBCMP_INC) $(LIBCMP_LIB) $(SECUTILS_LIB)

get_submodules: $(SECUTILS_DIR)/include $(LIBCMP_DIR)/include

update: update_secutils update_cmpossl
	git fetch
	git rebase

$(SECUTILS_DIR)/include: # not: update_secutils
	git submodule update $(GIT_PROGRESS) --init --depth 1 $(SECUTILS_DIR)

$(SECUTILS_LIB):
	build_secutils

.phony: update_secutils build_secutils
update_secutils:
	git submodule update $(GIT_PROGRESS) --init --depth 1 $(SECUTILS_DIR)
build_secutils: # not: update_secutils
	$(MAKE) -C $(SECUTILS_DIR) build DEBUG_FLAGS="$(DEBUG_FLAGS)" CFLAGS="$(CFLAGS) $(OSSL_VERSION_QUIRKS) $(SECUTILS_CONFIG_NO_ICV)" OPENSSL_DIR="$(OPENSSL_DIR)" OUT_DIR="$(OUT_DIR_REVERSE_DIR)"

$(LIBCMP_DIR)/include: # not: update_cmpossl
ifdef CMP_STANDALONE
	git submodule update $(GIT_PROGRESS) --init --depth 1 cmpossl
else
	mkdir -p $(LIBCMP_DIR)/include
endif

ifdef CMP_STANDALONE
$(LIBCMP_LIB): $(LIBCMP_INC)
	build_cmpossl
endif

.phony: update_cmpossl build_cmpossl
update_cmpossl:
	git submodule update $(GIT_PROGRESS) --init --depth 1 cmpossl
build_cmpossl: # not: update_cmpossl
	@ # the old way to build with CMP was: buildCMPforOpenSSL
ifdef CMP_STANDALONE
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp build DEBUG_FLAGS="$(DEBUG_FLAGS)" CFLAGS="$(CFLAGS)" OUT_DIR="$(OUT_DIR_REVERSE_DIR)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif

clean_submodules:
	rm -rf $(SECUTILS_DIR) cmpossl $(LIBCMP_LIB) $(SECUTILS_LIB)

endif # eq ($(SECUTILS_DIR),)

build_prereq: submodules
ifdef CMP_STANDALONE
    ifneq ($(wildcard $(LIBCMP_LIB)),)
	@export LIBCMP_OPENSSL_VERSION=`$(MAKE) -s --no-print-directory -f OpenSSL_version.mk LIB="$(LIBCMP_LIB)"` && \
	if [ "$$LIBCMP_OPENSSL_VERSION" != "$(OPENSSL_VERSION)" ]; then \
	    (echo "WARNING: OpenSSL version '$$LIBCMP_OPENSSL_VERSION' used for building libcmp does not match '$(OPENSSL_VERSION)' to be used for building client"; true); \
	fi
    endif
endif

build: build_prereq
	$(MAKE) -f Makefile_src $(OUTBIN) build DEBUG_FLAGS="$(DEBUG_FLAGS)" CFLAGS="$(CFLAGS)" OPENSSL_DIR="$(OPENSSL_DIR)" LIBCMP_INC="$(LIBCMP_INC)" OUT_DIR="$(OUT_DIR)" OSSL_VERSION_QUIRKS="$(OSSL_VERSION_QUIRKS)"

build_no_tls:
	$(MAKE) build DEBUG_FLAGS="$(DEBUG_FLAGS)" CFLAGS="$(CFLAGS)" SECUTILS_NO_TLS=1

.phony: clean_test clean clean_uta clean_this

ifeq ($(LPATH),)
clean_uta:
	$(MAKE) -C $(SECUTILS_DIR) clean_uta
endif

clean_test:
	rm -f creds/{manufacturer,operational*}.*
	rm -fr creds/crls
	rm -f cmpossl/test/recipes/80-test_cmp_http_data/*/test.*cert*.pem
	rm -f cmpossl/test/recipes/80-test_cmp_http_data/Simple
	rm -f test/faillog_*.txt
	rm -fr test/{Upstream,Downstream}

clean_this: clean_test
	$(MAKE) -f Makefile_src clean

clean: clean_this
ifeq ($(LPATH),)
	$(MAKE) -C $(SECUTILS_DIR) clean OUT_DIR="$(OUT_DIR_REVERSE_DIR)" || true
ifneq ("$(wildcard $(LIBCMP_DIR))","")
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp clean OUT_DIR="$(OUT_DIR_REVERSE_DIR)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif
endif
	rm -f doc/cmpClient-cli.md

ifneq ($(INSTA),)
    unreachable="cannot reach pki.certificate.fi"
    CA_SECTION=Insta
    OCSP_CHECK= #openssl ocsp -url "ldap://www.certificate.fi:389/CN=Insta Demo CA,O=Insta Demo,C=FI?caCertificate" -CAfile creds/trusted/InstaDemoCA.crt -issuer creds/trusted/InstaDemoCA.crt -cert creds/operational.crt
    override EXTRA_OPTS += -path pkix/ -newkeytype rsa:1024
else
    unreachable="cannot reach EJBCA at $$EJBCA_HOST"
    CA_SECTION=EJBCA
    OCSP_CHECK=openssl ocsp -url $$EJBCA_OCSP_URL \
               -CAfile $$EJBCA_CMP_TRUSTED -issuer $$EJBCA_CMP_ISSUER \
               -cert creds/operational.crt
    override EXTRA_OPTS +=
endif

creds/crls:
	mkdir $@

cmpossl/test/recipes/80-test_cmp_http_data/Simple:
	cd cmpossl/test/recipes/80-test_cmp_http_data && \
	ln -s ../../../../test/cmpossl/recipes/80-test_cmp_http_data/Simple

get_EJBCA_crls: | creds/crls
ifneq ($(EJBCA_ENABLED),)
	@ # ping >/dev/null $(PINGCOUNTOPT) 1 $(EJBCA_HOST)
	@ # || echo $(unreachable); exit 1
	@for CA in $$EJBCA_CDPS; \
	do \
		export ca=`echo $$CA | sed  's/\+//g; s/\.//;'`; \
		wget -q "$$EJBCA_CDP_URL_PREFIX$$CA$$EJBCA_CDP_URL_POSTFIX" -O "creds/crls/EJBCA-$$ca.crl"; \
	done
endif

get_Insta_crls: | creds/crls
	@ #curl -m 2 -s pki.certificate.fi ...
	$(SET_PROXY) wget -O /dev/null --tries=1 --max-redirect=0 --timeout=2 https://www.insta.fi/ --no-verbose
	@ # | fgrep "301 Moved Permanently" -q
	@ # || (echo $(unreachable); exit 1)
	@ #curl -s -o creds/crls/InstaDemoCA.crl ...
	@$(SET_PROXY) wget --quiet -O creds/crls/InstaDemoCA.crl "http://pki.certificate.fi:8081/crl-as-der/currentcrl-633.crl"

.phony: demo demo_Insta demo_EJBCA
demo: demo_Insta
demo_Insta:
	$(MAKE) run_demo INSTA=1 $(EJBCA_ENV)
demo_EJBCA:
	$(MAKE) run_demo INSTA=  $(EJBCA_ENV)

CMPCLIENT=$(SET_PROXY) LD_LIBRARY_PATH=. ./cmpClient$(EXE)
.phony: run_demo
ifeq ($(INSTA),)
run_demo: build get_EJBCA_crls
else
run_demo: build get_Insta_crls
endif
ifeq ($(EJBCA_ENABLED)$(INSTA),)
	$(warning "### skipping demo_EJBCA since not supported in this environment ###")
else
	@/bin/echo -e "\n##### running cmpClient demo #####\n"
	$(CMPCLIENT) imprint -section $(CA_SECTION) $(EXTRA_OPTS)
	@/bin/echo -e "\nValidating own CMP client cert"
    ifeq ($(INSTA),)
	$(CMPCLIENT) validate -cert $$EJBCA_CMP_CLIENT -tls_cert "" -own_trusted $$EJBCA_TRUSTED -untrusted $$EJBCA_UNTRUSTED
	@/bin/echo -e "\nValidating own TLS client cert"
	$(CMPCLIENT) validate -cert $$EJBCA_TLS_CLIENT -tls_trusted $$EJBCA_TRUSTED -untrusted $$EJBCA_UNTRUSTED
    else
	$(CMPCLIENT) validate -section Insta -tls_cert "" -cert creds/manufacturer.crt -own_trusted creds/trusted/InstaDemoCA.crt # -no_check_time
    endif
	@echo
	$(CMPCLIENT) bootstrap -section $(CA_SECTION) $(EXTRA_OPTS)
	openssl x509 -in creds/operational.crt -x509toreq -signkey creds/operational.pem -out creds/operational.csr -passin pass:12345
	openssl x509 -noout -text -in creds/operational.crt
	@echo :
	openssl x509 -noout -text -in creds/operational.crt | sed '/^         [0-9a-f].*/d'
	# @echo
	# $(CMPCLIENT) pkcs10 -section $(CA_SECTION)
	@echo
	$(CMPCLIENT) update -section $(CA_SECTION) $(EXTRA_OPTS)
	@echo :
	$(OCSP_CHECK)
	@echo
	@sleep 1 # for Insta helps avoid ERROR: server response error : Code=503,Reason=Service Unavailable
	$(CMPCLIENT) revoke -section $(CA_SECTION) $(EXTRA_OPTS)
	@echo :
	$(OCSP_CHECK)
	@echo -e "\n#### demo finished ####"
	@echo :
endif

.phony: start stop
start: #LightweightCmpRA
	java -jar $(CMPCAMOCK) . http://localhost:7000/ca creds/ENROLL_Keystore.p12 creds/CMP_CA_Keystore.p12 &
	mkdir test/Upstream test/Downstream 2>/dev/null || true
	java -jar $(LIGHTWEIGHTCMPRA) config/ConformanceTest.xml &
	@ # -Dorg.slf4j.simpleLogger.log.com.*=debug
	sleep 2
stop: #LightweightCmpRA
	PID=`ps aux|grep "java -jar $(CMPCAMOCK)"        | grep -v grep | awk '{ print $$2 }'` && \
	if [ -n "$$PID" ]; then kill $$PID; fi
	PID=`ps aux|grep "java -jar $(LIGHTWEIGHTCMPRA)" | grep -v grep | awk '{ print $$2 }'` && \
	if [ -n "$$PID" ]; then kill $$PID; fi

.phony: test_conformance_cmpclient test_conformance_openssl test_conformance
.phony: conformance_cmpclient conformance_openssl conformance
CMPCLNT = LD_LIBRARY_PATH=. ./cmpClient$(EXE) -section CmpRa,
CMPOSSL = LD_LIBRARY_PATH=$(OPENSSL_LIB_PATH) $(OPENSSL)$(EXE) cmp -config config/demo.cnf -section CmpRa,
test_conformance: start conformance_cmpclient conformance_openssl stop
test_conformance_openssl: start conformance_openssl stop
test_conformance_cmpclient: start conformance_cmpclient stop
conformance_cmpclient: build
	CMPCL="$(CMPCLNT)" make conformance $(EJBCA_ENV)
conformance_openssl: newkey
	CMPCL="$(CMPOSSL)" make conformance $(EJBCA_ENV)
newkey:
	openssl$(EXE) ecparam -genkey -name secp521r1 -out creds/manufacturer.pem
	openssl$(EXE) ecparam -genkey -name prime256v1 -out creds/operational.pem
conformance:
	$(CMPCL)imprint -server localhost:6002/lrawithmacprotection
	$(CMPCL)bootstrap
	openssl$(EXE) x509 -in creds/operational.crt -x509toreq -signkey creds/operational.pem -out creds/operational.csr -passin pass:12345
	$(CMPCL)pkcs10
	$(CMPCL)update -server localhost:6001 -path /rrkur
	$(CMPCL)revoke -server localhost:6001 -path /rrkur
	$(CMPCL)bootstrap -server localhost:6003/delayedlra

test_cli: build
ifeq ($(filter-out EJBCA Simple,$(OPENSSL_CMP_SERVER))$(EJBCA_ENABLED),)
	$(warning "### skipping test_$(OPENSSL_CMP_SERVER) since not supported in this environment ###")
else
	@echo -e "\n#### running CLI-based tests #### with server=$$OPENSSL_CMP_SERVER in cmpossl/test/recipes/80-test_cmp_http_data/$$OPENSSL_CMP_SERVER"
	@ :
	( HARNESS_ACTIVE=1 \
	  HARNESS_VERBOSE=$(V) \
          HARNESS_FAILLOG=../test/faillog_$$OPENSSL_CMP_SERVER.txt \
	  SRCTOP=cmpossl \
	  BLDTOP=. \
	  BIN_D=. \
	  EXE_EXT= \
	  LD_LIBRARY_PATH=$(BIN_D) \
          OPENSSL_CMP_CONFIG=test_config.cnf \
	  $(PERL) test/cmpossl/recipes/80-test_cmp_http.t )
	@ :
endif

test_Mock:
ifeq ($(shell expr $(OPENSSL_VERSION) \< 1.1),1) # OpenSSL <1.1 does not support -no_check_time nor OCSP
	$(warning skipping test_Mock since OpenSSL <1.1 does not support -no_check_time nor OCSP)
else
	make test_cli OPENSSL_CMP_SERVER=Mock $(EJBCA_ENV)
endif

.phony: test_Insta test_EJBCA-AWS
test_Insta: get_Insta_crls
	$(SET_PROXY) make test_cli OPENSSL_CMP_SERVER=Insta $(EJBCA_ENV)
test_EJBCA-AWS: get_EJBCA_crls
	$(SET_PROXY) make test_cli OPENSSL_CMP_SERVER=EJBCA $(EJBCA_ENV)

# do before: cd ~/p/genCMPClient/SimpleLra/ && ./RunLra.sh
test_Simple: get_EJBCA_crls cmpossl/test/recipes/80-test_cmp_http_data/Simple
ifeq ($(shell expr $(OPENSSL_VERSION) \< 1.1),1) # OpenSSL <1.1 does not support OCSP
	$(warning skipping certstatus aspect since OpenSSL <1.1 does not support OCSP)
	make test_cli OPENSSL_CMP_SERVER=Simple $(EJBCA_ENV) OPENSSL_CMP_ASPECTS="connection verification credentials commands enrollment"
else
	make test_cli OPENSSL_CMP_SERVER=Simple $(EJBCA_ENV)
endif

.phony: test_profile profile_Simple profile_EJBCA
test_profile: profile_Simple profile_EJBCA
# do before: cd ~/p/genCMPClient/SimpleLra/ && ./RunLra.sh
profile_Simple:
	PROFILE=Simple make profile $(EJBCA_ENV)
profile_EJBCA:
	PROFILE=EJBCA make profile $(EJBCA_ENV)
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
	echo "\n##### All profile tests succeeded #####"
endif

.phony: all test_all test_oss doc zip
all:	build doc

test_all: test_oss demo_EJBCA test_conformance test_profile test_Simple

test_oss: clean build_no_tls
	$(MAKE) clean build demo_Insta test_Mock test_Insta DEBUG_FLAGS="$(DEBUG_FLAGS)" CFLAGS="$(CFLAGS)"

doc: doc/cmpClient-cli.md
	$(MAKE) -C $(SECUTILS_DIR) doc

doc/cmpClient-cli.md: doc/cmpClient-cli.pod
	pod2markdown $< $@

zip:
	zip genCMPClient.zip \
            LICENSE.txt .md .gitmodules Makefile{,_src} CMakeLists.txt \
	    OpenSSL_version.{c,mk} include/genericCMPClient.h \
	    src/cmpClient.c src/genericCMPClient.c



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
deb:
	debuild -uc -us -I* --lintian-opts --profile debian
	rm -r debian/tmp

clean_deb:
	rm ../libgencmpcl*.deb

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
