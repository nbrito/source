BIN             = /bin
PREFIX          = /usr
USRBIN          = $(PREFIX)/bin
USRSBIN         = $(PREFIX)/sbin
MANDIR          = $(PREFIX)/share/man/man8

OSYSTEM         = `uname -s`

CC              = $(USRBIN)/gcc
#CFLAGS          = -Wall
#CFLAGS        += -Werror 
CFLAGS         += -O3 -mpreferred-stack-boundary=2
CFLAGS         += -march=i686
#CFLAGS         += -mcpu=i686 
#CFLAGS         += -D__HAVE_DEBUG__

LDFLAGS         = -m elf_i386
#LDFLAGS         += -static

INSTALL         = $(USRBIN)/install
INSTALL_OPTIONS = -c -p
INSTALL_PERMS   = -g wheel -o root -m 00700

RM              = $(BIN)/rm -f
MKDIR           = $(BIN)/mkdir

STRIP           = $(USRBIN)/strip
UPX             = $(USRBIN)/upx

OBJECTS         = getopt.o in_cksum.o b52.o options.o resolv.o sendraw.o usage.o
PROGRAM         = b52

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
	for file in $(OBJECTS) $(PROGRAM) .*.swp core; do\
		if [ -f $$file ]; then\
			$(RM) $$file 1>&2 > /dev/null;\
		fi;\
	done
