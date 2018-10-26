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

SECUTILS=securityUtilities
CMP_DIR=cmpossl

ifeq ($(OPENSSL_DIR),)
    OPENSSL_DIR=$(ROOTFS)/usr
endif
ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
# $(OPENSSL_DIR) is relative path, assumed relative to ./
    OPENSSL=../$(OPENSSL_DIR)
    OPENSSL_LIB=../$(OPENSSL_DIR)
else
# $(OPENSSL_DIR) is absolute path
    OPENSSL=$(OPENSSL_DIR)
    OPENSSL_LIB=$(OPENSSL)/lib
endif

OPENSSL_VERSION=$(shell fgrep OPENSSL_VERSION_NUMBER $(OPENSSL_DIR)/include/openssl/opensslv.h | sed -r 's/.*?NUMBER\s+//; s/L.*//')
ifeq ($(findstring 0x,$(OPENSSL_VERSION)),)
    $(error cannot determine version of OpenSSL in directory '$(OPENSSL_DIR)')
endif
ifeq ($(shell test $$(printf "%d" $(OPENSSL_VERSION)) -ge $$(printf "%d" 0x10102000); echo $$?),0)
    OSSL_VERSION_QUIRKS+=-D'DEPRECATEDIN_1_2_0(f)='
endif
ifeq ($(shell test $$(printf "%d" $(OPENSSL_VERSION)) -lt $$(printf "%d" 0x10100000); echo $$?),0)
    #$(info enabling compilation quirks for OpenSSL 1.0.2)
    OSSL_VERSION_QUIRKS+=-Wno-discarded-qualifiers -D'DEPRECATEDIN_1_1_0(f)=f;' -D'DEPRECATEDIN_1_0_0(f)='
endif

################################################################
# generic CMP Client lib and demo
################################################################

.phony: build clean clean_uta test all

ifndef USE_UTA
    export SEC_NO_UTA=1
endif

build:	# the old way to build with CMP was: buildCMPforOpenSSL
	cd $(SECUTILS) && git submodule update --init --recursive
	$(MAKE) -C $(SECUTILS) build OPENSSL_DIR="$(OPENSSL_DIR)"
	$(MAKE) -C cmpossl -f Makefile_cmp cmp_lib CMP_DIR=".." OPENSSL_DIR="$(OPENSSL)"
	$(MAKE) -C src build OPENSSL_DIR="$(OPENSSL_DIR)" CFLAGS="$(OSSL_VERSION_QUIRKS)" CMP_INC="$(CMP_INC)"

clean_uta:
	$(MAKE) -C $(SECUTILS) clean_uta

clean:
	$(MAKE) -C $(SECUTILS) clean
	$(MAKE) -C cmpossl -f Makefile_cmp cmp_clean CMP_DIR=".."  OPENSSL_DIR="$(OPENSSL)"
	$(MAKE) -C src clean
	rm -f certs/new.*

test:	build
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

allclean: clean
	$(MAKE) -C $(SECUTILS) clean #libclean
	rm -Rf $(DIRS)

.phony: buildCMPforOpenSSL
buildCMPforOpenSSL: openssl ${makeCMPforOpenSSL_trigger}


CMP_HDRS_=crmf.h cmp.h cmperr.h crmferr.h err.h safestack.h
CMP_HDRS = $(patsubst %,$(CMP_DIR)/include/openssl/%,$(CMP_HDRS_))

CMP_SRCS_ = cmp_asn.c cmp_ctx.c cmp_err.c cmp_http.c cmp_lib.c cmp_msg.c cmp_ses.c cmp_srv.c cmp_vfy.c
CRMF_SRCS_ = crmf_asn.c crmf_err.c crmf_lib.c crmf_pbm.c
CMP_SRCS = $(patsubst %,$(CMP_DIR)/crypto/crmf/%,$(CRMF_SRCS_)) $(patsubst %,$(CMP_DIR)/crypto/cmp/%,$(CMP_SRCS_))

#CMP_OBJS = $(CMP_SRCS:.c=$(OBJ))

CMP_OUT=.
CMP_INC=$(CMP_OUT)/include_cmp
CMP_LIB=$(CMP_OUT)/libcmp$(DLL)

CC=gcc
CFLAGS=-g -O0 -Werror $(OSSL_VERSION_QUIRKS) -fPIC -isystem $(CMP_INC) -isystem $(OPENSSL_DIR)/include # use and order of -isystem is critical
#CMP_HDRS_INC = $(patsubst %,-include %,$(CMP_HDRS)) # used to force inclusion order in source files $(CMP_SRCS)
CMP_HDRS_INC = -include openssl/crmf.h # used to force inclusion order in cmp_err.c

.phony: cmp_lib cmp_clean

cmp_lib: $(CMP_LIB)

#%$(OBJ): %.c
#	$(CC) $(CFLAGS) -c $< -o $@

$(CMP_LIB): $(CMP_HDRS) $(CMP_SRCS) # $(CMP_OBJS)
	mkdir -p $(CMP_OUT)
	mkdir -p $(CMP_INC)/openssl
	ln -srft $(CMP_INC)/openssl $(CMP_HDRS)
	$(CC) $(CFLAGS) $(CMP_HDRS_INC) $(CMP_SRCS) -shared -o $@

cmp_clean:
	rm -f $(CMP_LIB) # $(CMP_OBJS)
