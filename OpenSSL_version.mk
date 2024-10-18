# https://stackoverflow.com/questions/714100/os-detecting-makefile
ifeq ($(OS),Windows_NT) # strange but apparently this string is used also for all later versions
    OS=Windows
    # USERS="\\Users\\"
    $(warning [DEBUG] OS is $(OS))
    DLL = .dll
    EXE = .exe
else
    OS = $(shell sh -c 'uname 2>/dev/null || echo Unknown')
    ifeq ($(shell uname -s),Darwin)
        OS = MacOS
        # USERS="/Users/"
        DLL = .dylib
        $(warning [DEBUG] OS is Darwin ($(OS)))
    else
        $(warning [DEBUG] OS is supposed to be Unix-like: $(OS))
        # USERS="/home/"
        DLL = .so
    endif
    EXE =
endif

# https://stackoverflow.com/questions/17055773/how-to-synthesize-line-breaks-in-gnu-make-warnings-or-errors
define newline # the following two empty lines are essential


endef

ifeq ($(OPENSSL_DIR),) # for convenience, use heuristics to determine OPENSSL_DIR
    ifeq ($(OS),MacOS)
        SYSTEM_INCLUDE_OPENSSL=/opt/homebrew/include/openssl
    else
        SYSTEM_INCLUDE_OPENSSL=/usr/include/openssl
    endif
    OPENSSL_INCLUDE_DIR = $(realpath $(SYSTEM_INCLUDE_OPENSSL))
    OPENSSL_DIR = $(realpath $(OPENSSL_INCLUDE_DIR)/../..)
    $(warning [DEBUG] OPENSSL_DIR is detected as $(OPENSSL_DIR))
else
    $(warning [DEBUG] OPENSSL_DIR is set to $(OPENSSL_DIR))
endif

ifeq ($(OS),Windows)
    LIB = bin
else
    LIB = lib
endif

ifeq ($(OPENSSL_DIR),)
    $(warning Warning: OPENSSL_DIR is emtpy or not set, and was unable to determine it, trying to continue anyway)
else
    LIB_NAME_PATTERN=libcrypto*$(DLL)*
    OPENSSL_FULL_DIR = $(realpath $(OPENSSL_DIR))
    $(warning [DEBUG] OPENSSL_DIR expands to $(OPENSSL_FULL_DIR))
    ifeq ($(OPENSSL_FULL_DIR),)
        $(error OPENSSL_DIR appears to be an invalid path: $(OPENSSL_DIR))
    endif
    ifeq ($(OPENSSL_LIB),) # for convenience, use heuristics to determine OPENSSL_LIB
        OPENSSL_LIB = $(OPENSSL_DIR)/$(LIB)
        ifeq ($(wildcard $(OPENSSL_LIB)/$(LIB_NAME_PATTERN)),)
            $(warning Warning: cannot find OpenSSL libraries at determined location $(OPENSSL_LIB), now trying OPENSSL_DIR)
            OPENSSL_LIB = $(OPENSSL_DIR)
            ifeq ($(wildcard $(OPENSSL_LIB)/$(LIB_NAME_PATTERN)),)
                ifeq ($(OS),Linux)
                    OPENSSL_LIB_ = $(OPENSSL_LIB)
                    OPENSSL_LIB = $(wildcard /lib/*linux-gnu*)
                    $(warning Warning: cannot find OpenSSL libraries at $(OPENSSL_LIB_), now trying $(OPENSSL_LIB))
                endif
            endif
        endif
    else
        ifeq ($(wildcard $(OPENSSL_LIB)/$(LIB_NAME_PATTERN)),)
            $(warning Warning: cannot find OpenSSL libraries at given OPENSSL_LIB $(OPENSSL_LIB), now trying OPENSSL_DIR)
            OPENSSL_LIB = $(OPENSSL_DIR)
        endif
    endif
    # ifeq ($(shell echo $(OPENSSL_FULL_DIR) | grep $(USERS)),)
    #     $(warning [DEBUG] OPENSSL_DIR is assumed to be an installation directory)
    # else
    #     $(warning [DEBUG] OPENSSL_DIR is assumed to be a local build directory)
    # endif
    ifeq ($(wildcard $(OPENSSL_LIB)/$(LIB_NAME_PATTERN)),)
        $(warning Warning: cannot find OpenSSL library $(LIB_NAME_PATTERN) at $(OPENSSL_LIB)/, trying to continue anyway)
    endif
endif

ifneq ($(MAKECMDGOALS),dir)
ifneq ($(MAKECMDGOALS),lib)
$(warning [DEBUG] parameter SOURCE=$(SOURCE))
ifeq ($(SOURCE),)
    $(warning [DEBUG] SOURCE is empty (default))

    LDFLAGS += -L$(OPENSSL_LIB) -Wl,-rpath,$(OPENSSL_LIB)
    CFLAGS += -isystem $(OPENSSL_DIR)/include
    LDLIBS = -lcrypto

  # $(warning [TRACE] EXE=$(EXE))
    $(warning [TRACE] OPENSSL_DIR=$(OPENSSL_DIR))
    $(warning [TRACE] OPENSSL_LIB=$(OPENSSL_LIB))
    $(warning [TRACE] CFLAGS=$(CFLAGS))
    $(warning [TRACE] LDLIBS=$(LDLIBS))
    $(warning [TRACE] LDFLAGS=$(LDFLAGS)$(newline))

    .PHONY: default build show clean

    default: clean build show

    build: OpenSSL_version

    show: build fix_lib
	@./OpenSSL_version$(EXE)

    clean:
	@rm -f OpenSSL_version$(EXE)

else ifeq ($(SOURCE),header)
    # $(warning [DEBUG] SOURCE is 'header')
    OPENSSLV_H = $(OPENSSL_DIR)/include/openssl/opensslv.h
    ifeq ($(OPENSSL_DIR),)
        $(error missing OPENSSL_DIR, which is needed for reading OPENSSL_DIR$(OPENSSLV_H))
    endif
    $(warning [DEBUG] OPENSSLV_H=$(OPENSSLV_H))
    ifeq ($(shell fgrep OPENSSL_VERSION_MAJOR "$(OPENSSLV_H)"),)
        $(warning [DEBUG] OPENSSL_VERSION_MAJOR not found in OPENSSLV_H)
        OPENSSL_VERSION = $(shell grep 'OPENSSL_VERSION_TEXT\s* "OpenSSL ' "$(OPENSSLV_H)" \
                            | head -n 1 | sed -r 's/.*OpenSSL //' | awk '{print ($$0+0)}')
    else
        $(warning [DEBUG] OPENSSL_VERSION_MAJOR found in OPENSSLV_H)
        OPENSSL_VERSION = $(shell fgrep 'define OPENSSL_VERSION_M' "$(OPENSSLV_H)" \
                            | awk 'BEGIN { RS="" } {print $$4"."$$8 }')
        # $(warning [TRACE] After splitting OPENSSL_VERSION_MAJOR/MINOR: OPENSSL_VERSION=$(OPENSSL_VERSION))
    endif

    ifeq ($(OPENSSL_VERSION),1)
        OPENSSL_VERSION = 1.0
    endif
    $(warning [TRACE] OPENSSL_VERSION=$(OPENSSL_VERSION))

else # $(SOURCE) is name of library file (libcrypto or libsecutils or libcmp)
    $(warning [DEBUG] SOURCE is supposed to be a library file: $(SOURCE))
    ifeq ($(realpath $(SOURCE)),)
        $(error SOURCE appears to be an invalid file path name: $(SOURCE))
    endif

    # first try to find version string in library binary because this is more accurate than the file name
    OPENSSL_VERSION = $(shell strings "$(SOURCE)" | grep -E 'OpenSSL [0-9]+\.[0-9]+\.' \
                        | head -n 1 | sed -r 's/.*OpenSSL //' | awk -v FS="." '{print $$1"."$$2}')
    ifeq ($(OPENSSL_VERSION),)
        $(warning [DEBUG] OpenSSL version info not found in library file contents; now trying to get it from the libcrypto file name referenced)
        ifeq ($(findstring libcrypto,$(SOURCE)),)
            ifeq ($(OS),MacOS)
                LDD=otool -l
            else
                LDD=ldd
            endif
            STR=$(shell $(LDD) "$(SOURCE)" | grep -E 'libcrypto\.' | head -n 1)
            ifeq ($(STR),)
                $(error Error using '$(LDD)' to get the library dependencies in $(SOURCE))
            endif
        else
            STR="$(SOURCE)"
        endif
#       OPENSSL_VERSION = $(shell echo "'$(STR)'" | sed -r 's/.*libcrypto(\.\w+)?\.(\d+(\.d+)?)/$1/')
        OPENSSL_VERSION = $(shell echo "'$(STR)'" | sed -r 's/.*libcrypto(\.[[:alpha:]]+)?\.([[:digit:]](\.[[:digit:]]+)?).*/\2/')
    endif
    ifeq ($(OPENSSL_VERSION),1.0.0)
        OPENSSL_VERSION = 1.0
    endif

    $(warning [TRACE] OPENSSL_VERSION=$(OPENSSL_VERSION))

endif # $(SOURCE)
endif #neq ($(MAKECMDGOALS),lib
endif #neq ($(MAKECMDGOALS),dir)

.PHONY: detect # must be the first rule in this sequence
detect:
ifneq ($(SOURCE),)
    ifeq ($(shell echo "$(OPENSSL_VERSION)" | grep -E '^[[:digit:]]+(\.[[:digit:]]+)*$$'),)
        $(error Error detecting OpenSSL version from $(SOURCE))
    endif
endif
	@echo $(OPENSSL_VERSION)

.PHONY: dir
dir:
    ifeq ($(OPENSSL_DIR),)
        $(error Error determining OPENSSL_DIR)
    endif
	@echo "$(OPENSSL_DIR)"

.PHONY: lib
lib: fix_lib
    ifeq ($(OPENSSL_LIB),)
        $(error Error determining OPENSSL_LIB)
    endif
	@echo "$(OPENSSL_LIB)"

.PHONY: fix_lib
fix_lib:
ifneq ($(OPENSSL_LIB),)
    ifeq ($(OPENSSL_LIB),$(OPENSSL_DIR))
        ifeq ($(OS),MacOS)
	    @ # workaround for MacOS linkers insisting that library is to be found in lib/ directory,
	    @ # see for libs that dynamically link to OpenSSL the output of: otool -L <libname.dylib>
	    @cd "$(OPENSSL_DIR)"; if [ ! -e lib ]; then ln -s . lib; fi
	    @ # alternative would be to use, e.g.,
	    @ # install_name_tool -change $(OPENSSL_DIR)/lib/libcrypto.3.dylib $(OPENSSL_DIR)/libcrypto.3.dylib <libname.dylib>
        endif
    endif
endif
	@true # prevent "Nothing to be done for `fix_lib'."
