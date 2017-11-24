BIN             = /bin
PREFIX          = /usr
INCLUDE         = ./include
USRBIN          = $(PREFIX)/bin
USRSBIN         = $(PREFIX)/sbin
MANDIR          = $(PREFIX)/share/man/man8
RM              = $(BIN)/rm -f
MKDIR           = $(BIN)/mkdir
STRIP           = $(USRBIN)/strip
UPX             = $(USRBIN)/upx
OSYSTEM         = `uname -s`

CC              = $(USRBIN)/gcc
CFLAGS          = -xc
CFLAGS         += -Wmissing-field-initializers
CFLAGS         += -Wformat
CFLAGS         += -Wformat-nonliteral
CFLAGS         += -Wformat-security
CFLAGS         += -Wformat-y2k
CFLAGS         += -Wimplicit
CFLAGS         += -Waddress
CFLAGS         += -Warray-bounds
CFLAGS         += -Wcomments
CFLAGS         += -O3
CFLAGS         += -mpreferred-stack-boundary=12
CFLAGS         += -march=core2
CFLAGS         += -mtune=core2
CFLAGS         += -msse
CFLAGS         += -msse2
CFLAGS         += -msse3
CFLAGS         += -ffast-math
CFLAGS         += -funroll-loops
CFLAGS         += -fomit-frame-pointer
CFLAGS         += -lmpi
#CFLAGS         += -D__HAVE_DEBUG__
CFLAGS         += -I$(INCLUDE)

LD              = $(USRBIN)/ld
LDFLAGS         = -m elf_x86_64
#LDFLAGS         = -m elf_i386
#LDFLAGS        += -static

INSTALL         = $(USRBIN)/install
INSTALL_OPTIONS = -c -p
INSTALL_PERMS   = -g bin -o root -m 00700

OBJECTS         = f22.o in_cksum.o options.o resolv.o sendraw.o usage.o
PROGRAM         = f22

.c.o:
	@if [ $(OSYSTEM) != "Linux" ]; then\
		echo "Sorry! The $(PROGRAM) was only tested under Linux!";\
		exit 1;\
	fi
	$(CC) $(CFLAGS) -c $< -o $@

all: $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS)
	@if [ -f $(STRIP) ] && [ -e $(STRIP) ]; then\
		$(STRIP) -s $@ 1>&2 > /dev/null;\
	fi
	@if [ -f $(UPX) ] && [ -e $(UPX) ]; then\
		$(UPX) -9 -q $@ 1>&2 > /dev/null;\
	fi

install: $(PROGRAM)
	if [ ! -d $(USRSBIN) ]; then\
		$(MKDIR) $(USRSBIN);\
	fi
	$(INSTALL) $(INSTALL_OPTIONS) $< $(INSTALL_PERMS) $(USRSBIN)

uninstall: $(PROGRAM)
	if [ -f $(USRSBIN)/$(PROGRAM) ] && [ -e $(USRSBIN)/$(PROGRAM) ]; then\
		 $(RM) $(USRSBIN)/$(PROGRAM);\
	fi
	
clean:
	for file in $(OBJECTS) $(PROGRAM) *~ .*.swp core; do\
		if [ -f $$file ]; then\
			$(RM) $$file 1>&2 > /dev/null;\
		fi;\
	done
