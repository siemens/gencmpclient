ifeq ($(OS),Windows_NT)
    EXE=.exe
else
    EXE=
endif

#CC=gcc
ifneq ($(OPENSSL_DIR),)
    CFLAGS+=-I$(OPENSSL_DIR)/include
    LDFLAGS+=-L$(OPENSSL_DIR) -Wl,-rpath=$(OPENSSL_DIR)
endif
LDLIBS=-lcrypto

.phony: version clean

version: OpenSSL_version
	@./OpenSSL_version$(EXE)

clean:
	rm -f OpenSSL_version$(EXE)
