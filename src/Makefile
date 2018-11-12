# optional OPENSSL_DIR defines absolute or relative (to ../) path to OpenSSL installation

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

ifeq ($(OPENSSL_DIR),)
    OPENSSL_DIR=$(ROOTFS)/usr/
endif
ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
# $(OPENSSL_DIR) is relative path, assumed relative to ../
    OPENSSL=../$(OPENSSL_DIR)
    OPENSSL_LIB=$(OPENSSL)
    OPENSSL_RPATH=$(OPENSSL_DIR)
    OPENSSL_RPATH_LIB=$(OPENSSL_DIR)
else
# $(OPENSSL_DIR) is absolute path
    OPENSSL=$(OPENSSL_DIR)
    OPENSSL_LIB=$(OPENSSL)/lib
    OPENSSL_RPATH=$(OPENSSL)
    OPENSSL_RPATH_LIB=$(OPENSSL_LIB)
endif

PARENT_DIR=..
ARCHIVE=$(PARENT_DIR)/bin # for Jenkins
SECUTILS_=securityUtilities
SECUTILS=$(PARENT_DIR)/$(SECUTILS_)
CMP_INC ?= include_cmp

CC = gcc

override CFLAGS += -g -O0 -c -std=gnu90 -fmessage-length=0 -D_FORTIFY_SOURCE=2 -Wall -Werror -Woverflow #-Wconversion #-MMD -MP -MF"$(@:%$(OBJ)=%.d)" -MT"$(@)"  # -fsanitize=address
override CFLAGS += -I$(PARENT_DIR)/include -I$(SECUTILS)/include -I$(PARENT_DIR)/$(CMP_INC) -I$(OPENSSL)/include -DCMP_STANDALONE

LIBS = -lcmp -lSecUtils -lssl -lcrypto
ifdef USE_UTA
    LIBS += -luta
endif

LDFLAGS = -L$(SECUTILS) -Wl,-rpath=$(SECUTILS_) $(LIBS) -L$(PARENT_DIR)
LDFLAGS += -L$(OPENSSL_LIB) -L$(OPENSSL) -Wl,-rpath=$(OPENSSL_RPATH_LIB) -Wl,-rpath=$(OPENSSL_RPATH)

OBJS = genericCMPClient$(OBJ) cmpClientDemo$(OBJ)

SRCS = $(OBJS:$(OBJ)=.c)

DEPS = $(SRCS:.c=.d)

DLLS = *$(DLL)*

TGT = $(PARENT_DIR)/cmpClientDemo$(EXE)

########## targets

.PHONY: build
build:	$(TGT)
ifeq ($(OS),Windows_NT)
	@echo "Copying DLLs to base directory for convenient use with Windows"
	@cp -a $(SECUTILS)/$(DLLS) $(OPENSSL_LIB)/$(DLLS) $(PARENT_DIR) # --no-preserve=mode
endif

cmpClientDemo$(OBJ): cmpClientDemo.c $(PARENT_DIR)/include/genericCMPClient.h

genericCMPClient$(OBJ): genericCMPClient.c $(PARENT_DIR)/include/genericCMPClient.h

$(TGT): $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

$(DEPS): %.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

-include $(DEPS)

$(OBJS): %$(OBJ):%.c
	$(CC) $(CFLAGS) $< -o $@

#%$(OBJ): %.c
#	$(CC) $(CFLAGS) -o "$@" "$<"

.PHONY: all
all: build
	mkdir 2>/dev/null $(ARCHIVEDIR) || true
	rsync -a $(TGT) $(ARCHIVE)

.PHONY: clean
clean:
	rm -f $(TGT) $(OBJS) $(DEPS) $(PARENT_DIR)/$(DLLS)
