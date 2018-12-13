# optional LPATH defines absolute path where to find pre-installed libraries, e.g., /usr/lib
# optional OPENSSL_DIR defines absolute or relative (to ../) path to OpenSSL installation
# optional LIBCMP_INC defines absolute or relative (to ../) path of the libcmp header files
# optional LIBCMP_OUT defines absolute or relative (to ../) path of libcmp binary


ifeq ($(OS),Windows_NT)
    EXE=.exe
    DLL=.dll
    OBJ=.obj
    LIB=bin
else
    EXE=
    DLL=.so
    OBJ=.o
    LIB=lib
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
    OPENSSL_LIB=$(OPENSSL)/$(LIB)
    OPENSSL_RPATH=$(OPENSSL)
    OPENSSL_RPATH_LIB=$(OPENSSL_LIB)
endif

PARENT_DIR=..
ARCHIVE=$(PARENT_DIR)/bin # for Jenkins
LIBSECUTILS=libSecUtils$(DLL)
SECUTILS_DIR_=securityUtilities
SECUTILS_DIR=$(PARENT_DIR)/$(SECUTILS_DIR_)
LIBCMP_INC ?= include_cmp
LIBCMP_OUT ?= .

CC = gcc

ifdef NDEBUG
    override CFLAGS += -DNDEBUG=1
endif
override CFLAGS += -g -O0 -std=gnu90 -fmessage-length=0 -D_FORTIFY_SOURCE=2 -Werror -Wall -Woverflow -Wconversion -Wextra# # -pedantic -MMD -MP -MF"$(@:%$(OBJ)=%.d)" -MT"$(@)"  # -fsanitize=address
ifeq ($(LPATH),)
   override CFLAGS += -I$(SECUTILS_DIR)/include -I$(PARENT_DIR)/$(LIBCMP_INC)
endif
override CFLAGS += -I$(PARENT_DIR)/include
override CFLAGS += -isystem $(OPENSSL)/include# # use of -isystem is critical for selecting wanted OpenSSL version

LIBS = -lcmp -lSecUtils -lssl -lcrypto
ifdef USE_UTA
    LIBS += -luta
endif

ifeq ($(LPATH),)
    override LDFLAGS += -L$(PARENT_DIR)/$(LIBCMP_OUT) -Wl,-rpath=$(LIBCMP_OUT)
    override LDFLAGS += -L$(SECUTILS_DIR) -Wl,-rpath=$(SECUTILS_DIR_)
    override LDFLAGS += -L$(OPENSSL_LIB) -L$(OPENSSL) -Wl,-rpath=$(OPENSSL_RPATH_LIB) -Wl,-rpath=$(OPENSSL_RPATH)
else
    override LDFLAGS += -L$(LPATH)
endif


LIBGENCMPCL=$(PARENT_DIR)/libgencmpcl$(DLL)

OBJS = genericCMPClient$(OBJ) cmpClientDemo$(OBJ)

SRCS = $(OBJS:$(OBJ)=.c)

DEPS = $(SRCS:.c=.d)

OPENSSL_DLLS = *{crypto,ssl}*.dll

EXES = $(PARENT_DIR)/cmpClientDemo$(EXE)

########## rules and targets

.PHONY: build
build:	$(EXES)
ifeq ($(OS),Windows_NT)
ifeq ($(LPATH),)
	@echo "Copying OpenSSL DLLs to base directory for convenient use with Windows"
	@cp --preserve=timestamps $(OPENSSL_LIB)/$(OPENSSL_DLLS) $(PARENT_DIR)
endif
	@echo "Copying SecUtils DLL to base directory for convenient use with Windows"
	@cp --preserve=timestamps $(SECUTILS_DIR)/$(LIBSECUTILS) $(PARENT_DIR) # $(OPENSSL_LIB)/*{crypto,ssl}*.dll
endif

-include $(DEPS)

$(OBJS): %$(OBJ): %.c
	 $(CC) $(CFLAGS) -c -fPIC $< -o $@
	@$(CC) $(CFLAGS) -MM $< -MT $@ -MF $*.d

#%$(OBJ): %.c
#	$(CC) $(CFLAGS) -o "$@" "$<"

$(LIBGENCMPCL): genericCMPClient$(OBJ)
	$(CC) $^ $(LDFLAGS) $(LIBS) -shared -o $@

$(PARENT_DIR)/cmpClientDemo$(EXE): cmpClientDemo$(OBJ) | $(LIBGENCMPCL)
	$(CC) $(LDFLAGS) $< -lgencmpcl $(LIBS) -o $@

.PHONY: all archive
all: build archive

archive:
	@mkdir 2>/dev/null $(ARCHIVEDIR) || true
	@cp --preserve=timestamps $(EXES) $(ARCHIVE)

.PHONY: clean
clean:
	rm -f $(EXES) $(LIBGENCMPCL) $(DEPS) $(OBJS)
ifeq ($(OS),Windows_NT)
ifeq ($(LPATH),)
	rm -f $(PARENT_DIR)/$(OPENSSL_DLLS)
endif
	rm -f $(PARENT_DIR)/$(LIBSECUTILS)
endif
