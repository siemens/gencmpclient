GENCMPCL_DIR = ../genCMPClient
OPENSSL_DIR = /usr
OUT_DIR = $(abspath .)
BIN_DIR = $(abspath .)
mode = debug

override CFLAGS += -Wall -std=gnu99 -fPIC -D__linux__

ifeq ($(mode), release)
    DEBUG_FLAGS ?= -O2
    override DEBUG_FLAGS += -DNDEBUG=1
else
    override DEBUG_FLAGS += -g -O0 -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all
endif

.PHONY: build clean

build:
	make -C $(GENCMPCL_DIR) build OPENSSL_DIR="$(OPENSSL_DIR)" CFLAGS="$(CFLAGS)" DEBUG_FLAGS="$(DEBUG_FLAGS)" CMP_STANDALONE=1 OUT_DIR="$(OUT_DIR)" BIN_DIR="$(BIN_DIR)"

clean:
ifneq ($(wildcard genCMPClient/Makefile),)
	make -C $(GENCMPCL_DIR) clean CMP_STANDALONE=1 OUT_DIR="$(OUT_DIR)" BIN_DIR="$(BIN_DIR)"
endif
