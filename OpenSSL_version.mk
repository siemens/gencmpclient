ifeq ($(OS),Windows_NT)
    EXE=.exe
    LIB=bin
else
    EXE=
    LIB=lib
endif

#CC=gcc
ifneq ($(OPENSSL_DIR),)
    ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
    # $(OPENSSL_DIR) is relative path
        OPENSSL_LIB=$(OPENSSL_DIR)
    else
    # $(OPENSSL_DIR) is absolute path
        OPENSSL_LIB=$(OPENSSL_DIR)/$(LIB)
    endif
    CFLAGS+=-I$(OPENSSL_DIR)/include
    LDFLAGS+=-L$(OPENSSL_LIB) -Wl,-rpath=$(OPENSSL_LIB)
endif
LDLIBS=-lcrypto

.phony: version clean

version: OpenSSL_version
	@./OpenSSL_version$(EXE)

clean:
	rm -f OpenSSL_version$(EXE)
