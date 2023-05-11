# adapt as needed:
GENCMPCL_DIR ?= ../gencmpclient
OPENSSL_DIR ?= /usr
OPENSSL_LIB ?= /lib/x86_64-linux-gnu
OUT_DIR ?= $(abspath .)
BIN_DIR ?= $(abspath .)
# mode ?= release
USE_LIBCMP ?= 1

override CFLAGS += -Wall -std=gnu99 -fPIC -D__linux__

ifeq ($(mode),release)
    DEBUG_FLAGS ?= -O2
    override DEBUG_FLAGS += -DNDEBUG=1
else
    override DEBUG_FLAGS += -g -O0 -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all
endif

.PHONY: build clean

build:
	make -C $(GENCMPCL_DIR) -f Makefile_v1 build USE_LIBCMP=$(USE_LIBCMP) OUT_DIR="$(OUT_DIR)" BIN_DIR="$(BIN_DIR)" OPENSSL_DIR="$(OPENSSL_DIR)" OPENSSL_LIB="$(OPENSSL_LIB)" CFLAGS="$(CFLAGS)" DEBUG_FLAGS="$(DEBUG_FLAGS)"

demo:
	make -C $(GENCMPCL_DIR) -f Makefile_v1 demo USE_LIBCMP=$(USE_LIBCMP) OUT_DIR="$(OUT_DIR)" BIN_DIR="$(BIN_DIR)" OPENSSL_DIR="$(OPENSSL_DIR)" OPENSSL_LIB="$(OPENSSL_LIB)" CFLAGS="$(CFLAGS)" DEBUG_FLAGS="$(DEBUG_FLAGS)"

clean:
	make -C $(GENCMPCL_DIR) -f Makefile_v1 clean USE_LIBCMP=$(USE_LIBCMP) OUT_DIR="$(OUT_DIR)" BIN_DIR="$(BIN_DIR)" OPENSSL_DIR="$(OPENSSL_DIR)"
