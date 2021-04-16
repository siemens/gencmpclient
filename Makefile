# optional LIB_OUT defines absolute or relative path where libcmp, libgencmpcl, and libsecutils shall be produced
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
    SECUTILS=libsecutils
    SECUTILS_LIB=$(SECUTILS)/libsecutils$(DLL)
    LIB_OUT ?= .
else
    OPENSSL_DIR ?= $(LPATH)/..
    LIB_OUT ?= $(LPATH)
endif
LIBCMP_LIB=$(LIB_OUT)/libcmp$(DLL)

ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
# $(OPENSSL_DIR) is relative path, assumed relative to ./
    OPENSSL_REVERSE_DIR=../$(OPENSSL_DIR)
else
# $(OPENSSL_DIR) is absolute path
    OPENSSL_REVERSE_DIR=$(OPENSSL_DIR)
endif

ifeq ($(shell echo $(LIB_OUT) | grep "^/"),)
# $(LIB_OUT) is relative path, assumed relative to ./
    LIB_OUT_REVERSE_DIR=../$(LIB_OUT)
else
# $(LIB_OUT) is absolute path
    LIB_OUT_REVERSE_DIR=$(LIB_OUT)
endif

#ifeq ($(findstring clean,$(MAKECMDGOALS)),)
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),clean_all)
ifneq ($(MAKECMDGOALS),clean_test)
OPENSSL_VERSION=$(shell $(MAKE) -s --no-print-directory -f OpenSSL_version.mk LIB=h OPENSSL_DIR="$(OPENSSL_DIR)")
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
	CMP_STANDALONE=1
endif
endif
endif
endif

ifeq ($(LPATH),)
    LIBCMP_DIR=cmpossl
    ifdef CMP_STANDALONE
        LIBCMP_INC=$(LIBCMP_DIR)/include_cmp
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

.phony: default build build_prereq
default: build

.phony: test all zip

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
ifeq ($(SECUTILS),)
submodules:
else
.phony: get_submodules build_submodules clean_submodules
submodules: build_submodules

build_submodules: get_submodules build_cmpossl build_secutils # $(LIBCMP_INC) $(LIBCMP_LIB) $(SECUTILS_LIB)

get_submodules: $(SECUTILS)/include $(LIBCMP_DIR)/include

update: update_secutils update_cmpossl
	git pull

$(SECUTILS)/include: # not: update_secutils
	git submodule update $(GIT_PROGRESS) --init $(SECUTILS)

$(SECUTILS_LIB):
	build_secutils

.phony: update_secutils build_secutils
update_secutils:
	git submodule update $(GIT_PROGRESS) --init $(SECUTILS)
build_secutils: # not: update_secutils
	$(MAKE) -C $(SECUTILS) build CFLAGS="$(CFLAGS) $(OSSL_VERSION_QUIRKS) $(SECUTILS_CONFIG_NO_ICV)" OPENSSL_DIR="$(OPENSSL_DIR)" OUT_DIR="$(LIB_OUT_REVERSE_DIR)"

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
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp build LIBCMP_INC="../$(LIBCMP_INC)" LIBCMP_DIR="$(LIB_OUT_REVERSE_DIR)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif

clean_submodules:
	rm -rf $(SECUTILS) cmpossl $(LIBCMP_LIB) $(SECUTILS_LIB)

endif # eq ($(SECUTILS),)

build_prereq: submodules
ifdef CMP_STANDALONE
	@export LIBCMP_OPENSSL_VERSION=`$(MAKE) -s --no-print-directory -f OpenSSL_version.mk LIB="$(LIBCMP_LIB)"` && \
	if [ "$$LIBCMP_OPENSSL_VERSION" != "$(OPENSSL_VERSION)" ]; then \
	    (echo "WARNING: OpenSSL version $$LIBCMP_OPENSSL_VERSION used for building libcmp does not match $(OPENSSL_VERSION) to be used for building client"; true); \
	fi
endif

build: build_prereq
	$(MAKE) -f Makefile_src $(OUTBIN) build OPENSSL_DIR="$(OPENSSL_DIR)" LIBCMP_INC="$(LIBCMP_INC)" LIB_DIR="$(LIB_OUT)" CFLAGS="$(CFLAGS)" OSSL_VERSION_QUIRKS="$(OSSL_VERSION_QUIRKS)"

.phony: clean_test clean clean_uta clean_all

ifeq ($(LPATH),)
clean_uta:
	$(MAKE) -C $(SECUTILS) clean_uta
endif

clean_test:
	rm -f creds/{manufacturer,operational*}.*
	rm -fr creds/crls
	rm -f cmpossl/test/recipes/81-test_cmp_cli_data/*/test.*cert*.pem
	rm -f cmpossl/test/recipes/81-test_cmp_cli_data/Simple
	rm -f test/faillog_*.txt
	rm -fr test/{Upstream,Downstream}

clean: clean_test
	$(MAKE) -f Makefile_src clean

clean_all: clean
ifeq ($(LPATH),)
	$(MAKE) -C $(SECUTILS) OUT_DIR="$(LIB_OUT_REVERSE_DIR)" clean || true
ifneq ("$(wildcard $(LIBCMP_DIR))","")
	$(MAKE) -C $(LIBCMP_DIR) -f Makefile_cmp clean LIBCMP_INC="../$(LIBCMP_DIR)/include_cmp" LIBCMP_DIR="$(LIB_OUT_REVERSE_DIR)" OPENSSL_DIR="$(OPENSSL_REVERSE_DIR)"
endif
endif

PROXY ?= http_proxy=http://de.coia.siemens.net:9400 https_proxy=$$http_proxy no_proxy=ppki-playground.ct.siemens.com # or, e.g., tsy1.coia.siemens.net = 194.145.60.1:9400

ifdef INSTA
    unreachable="cannot reach pki.certificate.fi"
    CA_SECTION=Insta
    OCSP_CHECK= #openssl ocsp -url "ldap://www.certificate.fi:389/CN=Insta Demo CA,O=Insta Demo,C=FI?caCertificate" -CAfile creds/trusted/InstaDemoCA.crt -issuer creds/trusted/InstaDemoCA.crt -cert creds/operational.crt
    override EXTRA_OPTS += -path pkix/ -newkeytype rsa:1024
else
    unreachable="cannot reach ppki-playground.ct.siemens.com"
    CA_SECTION=EJBCA
    OCSP_CHECK=openssl ocsp -url http://ppki-playground.ct.siemens.com/ejbca/publicweb/status/ocsp \
               -CAfile creds/trusted/PPKIPlaygroundECCRootCAv10.crt -issuer creds/PPKIPlaygroundECCIssuingCAv10.crt \
               -cert creds/operational.crt
#              -CAfile creds/trusted/PPKIPlaygroundInfrastructureRootCAv10.crt -issuer creds/PPKIPlaygroundInfrastructureIssuingCAv10.crt \
    override EXTRA_OPTS +=
endif

creds/crls:
	mkdir $@

cmpossl/test/recipes/81-test_cmp_cli_data/Simple:
	cd cmpossl/test/recipes/81-test_cmp_cli_data && \
	ln -s ../../../../test/cmpossl/recipes/81-test_cmp_cli_data/Simple

get_PPKI_crls: | creds/crls
	@ # ping >/dev/null $(PINGCOUNTOPT) 1 ppki-playground.ct.siemens.com
	@ # || echo $(unreachable); exit 1
	@for CA in 'Infrastructure+Root+CA+v1.0' 'Infrastructure+Issuing+CA+v1.0' 'ECC+Root+CA+v1.0' 'RSA+Root+CA+v1.0'; \
	do \
		export ca=`echo $$CA | sed  's/\+//g; s/\.//;'`; \
		wget -q "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+$$CA%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" -O "creds/crls/PPKIPlayground$$ca.crl"; \
	done

get_Insta_crls: | creds/crls
	@ #curl -m 2 -s pki.certificate.fi ...
	$(PROXY) wget -O /dev/null --tries=1 --max-redirect=0 --timeout=2 https://www.insta.fi/ --no-verbose
	@ # | fgrep "301 Moved Permanently" -q
	@ # || (echo $(unreachable); exit 1)
	@ #curl -s -o creds/crls/InstaDemoCA.crl ...
	@$(PROXY) wget --quiet -O creds/crls/InstaDemoCA.crl "http://pki.certificate.fi:8081/crl-as-der/currentcrl-633.crl"

ifndef INSTA
demo: build get_PPKI_crls
else
demo: build get_Insta_crls
endif
	@/bin/echo -e "\n##### running cmpClient demo #####"
	@/bin/echo -e ""
	$(PROXY) ./cmpClient$(EXE) imprint -section $(CA_SECTION) $(EXTRA_OPTS)
	@/bin/echo -e "\nValidating own CMP client cert"
ifndef INSTA
	./cmpClient validate -cert creds/ppki_playground_cmp.p12 -tls_cert "" -own_trusted creds/trusted/PPKIPlaygroundInfrastructureRootCAv10.crt -untrusted creds/PPKIPlaygroundInfrastructureIssuingCAv10.crt
	@/bin/echo -e "\nValidating own TLS client cert"
	./cmpClient validate -cert creds/ppki_playground_tls.p12 -tls_trusted creds/trusted/PPKIPlaygroundInfrastructureRootCAv10.crt -untrusted creds/PPKIPlaygroundInfrastructureIssuingCAv10.crt
else
	./cmpClient validate -section Insta -tls_cert "" -cert creds/manufacturer.crt -own_trusted creds/trusted/InstaDemoCA.crt # -no_check_time
endif
	@echo
	$(PROXY) ./cmpClient$(EXE) bootstrap -section $(CA_SECTION) $(EXTRA_OPTS)
	openssl x509 -in creds/operational.crt -x509toreq -signkey creds/operational.pem -out creds/operational.csr -passin pass:12345
	openssl x509 -noout -text -in creds/operational.crt
	@echo :
	openssl x509 -noout -text -in creds/operational.crt | sed '/^         [0-9a-f].*/d'
	# @echo
	# ./cmpClient pkcs10 -section $(CA_SECTION)
	@echo
	$(PROXY) ./cmpClient$(EXE) update -section $(CA_SECTION) $(EXTRA_OPTS)
	@echo :
	$(OCSP_CHECK)
	@echo
	@sleep 1 # for INSTA helps avoid ERROR: server response error : Code=503,Reason=Service Unavailable
	$(PROXY) ./cmpClient$(EXE) revoke -section $(CA_SECTION) $(EXTRA_OPTS)
	@echo :
	$(OCSP_CHECK)
	@echo -e "\n#### demo finished ####"
	@echo :

demo_Insta:
	INSTA=1 $(MAKE) demo

test_cli: build
	@echo -e "\n#### running CLI-based tests #### with server=$$OPENSSL_CMP_SERVER in cmpossl/test/recipes/81-test_cmp_cli_data/$OPENSSL_CMP_SERVER"
	@ :
	( HARNESS_ACTIVE=1 \
	  HARNESS_VERBOSE=$(V) \
          HARNESS_FAILLOG=faillog_$$OPENSSL_CMP_SERVER.txt \
	  SRCTOP=cmpossl \
	  BLDTOP=. \
	  BIN_D=. \
	  EXE_EXT= \
	  LD_LIBRARY_PATH=$(BIN_D) \
          OPENSSL_CMP_CONFIG=test_config.cnf \
	  $(PERL) test/cmpossl/recipes/81-test_cmp_cli.t )
	@ :

.phony: start_LightweightCmpRA kill_LightweightCmpRA
start_LightweightCmpRA:
	java -jar CmpCaMock.jar . http://localhost:7000/ca creds/ENROLL_Keystore.p12 creds/CMP_CA_Keystore.p12 2>/dev/null &
	mkdir test/Upstream test/Downstream 2>/dev/null || true
	java -jar LightweightCmpRa.jar config/ConformanceTest.xml 2>/dev/null &
	@ # -Dorg.slf4j.simpleLogger.log.com.siemens=debug
	sleep 2

kill_LightweightCmpRA:
	PID=`ps aux|grep "java -jar CmpCaMock.jar"        | grep -v grep | awk '{ print $$2 }'` && \
	if [ -n "$$PID" ]; then kill $$PID; fi
	PID=`ps aux|grep "java -jar LightweightCmpRa.jar" | grep -v grep | awk '{ print $$2 }'` && \
	if [ -n "$$PID" ]; then kill $$PID; fi

.phony: test_conformance test_conformance_cmpossl
test_conformance: build start_LightweightCmpRA
	./cmpClient imprint -section CmpRa -server localhost:6002/lrawithmacprotection
	./cmpClient bootstrap -section CmpRa
	openssl x509 -in creds/operational.crt -x509toreq -signkey creds/operational.pem -out creds/operational.csr -passin pass:12345
	./cmpClient pkcs10 -section CmpRa
	./cmpClient update -section CmpRa -server localhost:6001 -path /rrkur
	./cmpClient revoke -section CmpRa -server localhost:6001 -path /rrkur
	./cmpClient bootstrap -section CmpRa -server localhost:6003/delayedlra
	make kill_LightweightCmpRA

CMPOSSL=./openssl cmp -config config/demo.cnf -section CmpRa,
test_conformance_cmpossl: build start_LightweightCmpRA
	./openssl ecparam -genkey -name secp521r1 -out creds/manufacturer.pem
	$(CMPOSSL)imprint -server localhost:6002/lrawithmacprotection
	./openssl ecparam -genkey -name prime256v1 -out creds/operational.pem
	$(CMPOSSL)bootstrap
	./openssl x509 -in creds/operational.crt -x509toreq -signkey creds/operational.pem -out creds/operational.csr -passin pass:12345
	$(CMPOSSL)pkcs10
	$(CMPOSSL)update -server localhost:6001 -path /rrkur
	$(CMPOSSL)revoke -server localhost:6001 -path /rrkur
	$(CMPOSSL)bootstrap -server localhost:6003/delayedlra
	make kill_LightweightCmpRA

test_Simple: get_PPKI_crls cmpossl/test/recipes/81-test_cmp_cli_data/Simple
	make test_cli OPENSSL_CMP_SERVER=Simple

test_Mock:
	make test_cli OPENSSL_CMP_SERVER=Mock

test_Insta: get_Insta_crls
	$(PROXY) make test_cli OPENSSL_CMP_SERVER=Insta

test_profile: build
	@/bin/echo -e "\n##### Request a certificate from a PKI with MAC protection (RECOMMENDED) #####"
	./cmpClient$(EXE) -config config/profile.cnf -section 'Simple,EE04'
	@/bin/echo -e "\n##### Request a certificate from a new PKI with signature protection (REQUIRED) #####"
	./cmpClient$(EXE) -config config/profile.cnf -section 'Simple,EE01'
	@/bin/echo -e "\n##### Update an existing certificate with signature protection (REQUIRED) #####"
	./cmpClient$(EXE) -config config/profile.cnf -section 'Simple,EE02'
	@/bin/echo -e "\n##### Request a certificate from a trusted PKI with signature protection (OPTIONAL) #####"
	./cmpClient$(EXE) -config config/profile.cnf -section 'Simple,EE03'
	@/bin/echo -e "\n##### Revoking a certificate (RECOMMENDED) #####"
	./cmpClient$(EXE) -config config/profile.cnf -section 'Simple,EE09'
	@/bin/echo -e "\n##### Error reporting by EE (REQUIRED) #####"
	! ./cmpClient$(EXE) -config config/profile.cnf -section 'Simple,EE10'
	@/bin/echo -e "\n##### Error reporting by RA (REQUIRED) #####"
	! ./cmpClient$(EXE) -config config/profile.cnf -section 'Simple,RA11'
	echo "\n##### All profile tests succeeded #####"

all:	build doc test

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
OUTBIN=$(LIB_OUT)/libgencmpcl$(DLL)

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
