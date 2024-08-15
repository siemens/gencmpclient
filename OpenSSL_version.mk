ifeq ($(LIB),)
    $(info [DEBUG] LIB is empty or not set)

    ifeq ($(OS),Windows_NT)
        $(info [DEBUG] OS is Windows_NT)
        EXE = .exe
        LIB = bin
    else
        $(info [DEBUG] OS is supposed to be Unix-like)
        EXE =
        LIB = lib
        ifeq ($(shell uname -s),Darwin)
            $(info [DEBUG] OS is Darwin (MacOS))
            OS = MacOS
        endif
    endif

    CFLAGS+=-isystem $(OPENSSL_DIR)/include
    LDFLAGS+=-L$(OPENSSL_DIR) -L$(OPENSSL_LIB) -Wl,-rpath,$(OPENSSL_DIR) -Wl,-rpath,$(OPENSSL_LIB)
    LDLIBS=-lcrypto

    # CC = gcc
    ifneq ($(OPENSSL_DIR),)
        $(info [DEBUG] OPENSSL_DIR is set: $(OPENSSL_DIR))
        ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
            $(info [DEBUG] OPENSSL_DIR is a relative path)
            # $(OPENSSL_DIR) is relative path
            OPENSSL_LIB = $(OPENSSL_DIR)
        else
            $(info [DEBUG] OPENSSL_DIR is an absolute path)
            # $(OPENSSL_DIR) is absolute path
            OPENSSL_LIB = $(OPENSSL_DIR)/$(LIB)
        endif
        $(info [TRACE] After OPENSSL_DIR check: OPENSSL_LIB="$(OPENSSL_LIB)")
        CFLAGS += -isystem $(OPENSSL_DIR)/include
        LDFLAGS += -L$(OPENSSL_DIR) -L$(OPENSSL_LIB) -Wl,-rpath,$(OPENSSL_DIR) -Wl,-rpath,$(OPENSSL_LIB)
    endif

    LDLIBS = -lcrypto

    $(info [TRACE] After OPENSSL_DIR set: EXE=$(EXE))
    $(info [TRACE] After OPENSSL_DIR set: LIB=$(LIB))
    $(info [TRACE] After OPENSSL_DIR set: OPENSSL_LIB=$(OPENSSL_LIB))
    $(info [TRACE] After OPENSSL_DIR set: CFLAGS=$(CFLAGS))
    $(info [TRACE] After OPENSSL_DIR set: LDFLAGS=$(LDFLAGS))
    $(info [TRACE] After OPENSSL_DIR set: LDLIBS=$(LDLIBS))

    .PHONY: default build show clean

    default: build show clean

    build: OpenSSL_version

    show: build
	@./OpenSSL_version$(EXE)

    clean:
	@rm -f OpenSSL_version$(EXE)

else ifeq ($(LIB),header)
    $(info [DEBUG] LIB is set to header)

    OPENSSL_NUMBER_SEL = head -n 1 | sed -r 's/.*OpenSSL //' | awk '{print ($$0+0)}'
    OPENSSLV_H = $(OPENSSL_DIR)/include/openssl/opensslv.h
    ifeq ($(shell fgrep OPENSSL_VERSION_MAJOR "$(OPENSSLV_H)"),)
        $(info [DEBUG] OPENSSL_VERSION_MAJOR not found in OPENSSLV_H)
        OPENSSL_VERSION = $(shell grep 'OPENSSL_VERSION_TEXT\s* "OpenSSL ' "$(OPENSSLV_H)" | $(OPENSSL_NUMBER_SEL))
    else
        $(info [DEBUG] OPENSSL_VERSION_MAJOR found in OPENSSLV_H)
        ifeq ($(OS),MacOS)
            $(info [DEBUG] OS is MacOS)
            OPENSSL_VERSION = $(shell fgrep OPENSSL_VERSION_M "$(OPENSSLV_H)" | head -n 2 | awk -v RS="" '{print $4"."$8 }')
        else
            $(info [DEBUG] OS is not MacOS)
            OPENSSL_VERSION = $(shell fgrep OPENSSL_VERSION_M "$(OPENSSLV_H)" | head -n 2 | awk -v RS="" '{print $$4"."$$8 }')
        endif
        $(info [TRACE] After OS check in header: OPENSSL_VERSION=$(OPENSSL_VERSION))
    endif

    ifeq ($(OPENSSL_VERSION),1)
        OPENSSL_VERSION = 1.0
    endif

    $(info [TRACE] OPENSSL_NUMBER_SEL=$(OPENSSL_NUMBER_SEL))
    $(info [TRACE] OPENSSLV_H=$(OPENSSLV_H))
    $(info [TRACE] OPENSSL_VERSION=$(OPENSSL_VERSION))

else # $(LIB) is name of library file
    $(info [DEBUG] LIB is supposed to be a library file: $(LIB))

    OPENSSL_VERSION = $(shell strings "$(LIB)" | grep -E 'OpenSSL [0-9]+\.[0-9]+\.' | head -n 1 | sed -r 's/.*OpenSSL //' | awk -v FS="." '{print $$1"."$$2}')
    ifeq ($(OPENSSL_VERSION),)
        $(info [DEBUG] OpenSSL version info not found in library file contents; now trying to get it from the file name)
        OPENSSL_VERSION = $(shell strings "$(LIB)" | grep -E 'libcrypto\.' | head -n 1 | sed -r 's/.*libcrypto(.[a-z]+)?\.//')
    endif
    ifeq ($(OPENSSL_VERSION),1.0.0)
        OPENSSL_VERSION = 1.0
    endif

    $(info [TRACE] OPENSSL_VERSION=$(OPENSSL_VERSION))

endif # $(LIB)

.PHONY: detect

detect:
	$(info $(OPENSSL_VERSION))
