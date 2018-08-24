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

ARCHIVE=../bin # for Jenkins
SECUTILS=../securityUtilities

CC = gcc

CFLAGS = -g -O0 -c -std=gnu90 -fmessage-length=0 -D_FORTIFY_SOURCE=2 -Wall -Werror -Woverflow #-Wconversion #-MMD -MP -MF"$(@:%$(OBJ)=%.d)" -MT"$(@)"  # -fsanitize=address
CFLAGS += -I$(SECUTILS)/include -I../$(SECUTILS)/include -I../include

LIBS = -lSecUtils -lcrypto -lssl -lxml2 -luta -lz -lm -lpthread # -lssl -lcrypto -lxmlsec1 -lxml2

LDFLAGS = -L$(SECUTILS)/$(LIB) -L$(SECUTILS)/lib -Wl,-rpath=securityUtilities/lib $(LIBS) # -Wl,-rpath=.. #-Wl,-rpath-link,../

OBJS = genericCMPClient$(OBJ) cmpClientDemo$(OBJ)

SRCS = $(OBJS:$(OBJ)=.c)

DEPS = $(SRCS:.c=.d)

DLLS = *$(DLL)*

TGT = ../cmpClientDemo$(EXE)

########## targets

.PHONY: all
all:	$(TGT)
ifeq ($(OS),Windows_NT)
	@echo "Copying DLLs to base directory for convenient use with Windows"
	@cp -a $(SECUTILS)/$(LIB)/$(DLLS) .. || true # --no-preserve=mode
endif

cmpClientDemo$(OBJ): cmpClientDemo.c ../include/genericCMPClient.h

genericCMPClient$(OBJ): genericCMPClient.c ../include/genericCMPClient.h

$(TGT): $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

$(DEPS): %.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

# TODO: dependency on certMgr/genericCMPClient.h is not used
include $(DEPS) # fires also for 'make clean' :(

$(OBJS): %$(OBJ):%.c
	$(CC) $(CFLAGS) $< -o $@

#%$(OBJ): %.c
#	$(CC) $(CFLAGS) -o "$@" "$<"

.PHONY: build
build: all
	mkdir 2>/dev/null $(ARCHIVEDIR) || true
	rsync -a $(TGT) $(ARCHIVE)

.PHONY: clean
clean:
	rm -f $(TGT) $(OBJS) $(DEPS) ../$(DLLS)
