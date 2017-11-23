#  Copyright© 2004-2008 Nelson Brito
#  This file is part of the ENG Private Tool by Nelson Brito.

#  This program is free software; you can redistribute it and/or modify it under
#  the terms of the GNU General Public License  version 2, 1991  as published by
#  the Free Software Foundation.

#  This program is distributed  in the hope that it will be useful,  but WITHOUT
#  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#  FOR A PARTICULAR PURPOSE.  
  
#  See the GNU General Public License for more details.

#  A copy of the GNU General Public License can be found at:
#  http://www.gnu.org/licenses/gpl.html
#  or you can write to:
#  Free Software Foundation, Inc.
#  59 Temple Place - Suite 330
#  Boston, MA  02111-1307
#  USA.

# Nelson Brito <nbrito@sekure.org>
# $Id: Makefile,v 1.7 2008-09-14 13:16:42-03 nbrito Exp $

BIN             = /bin
PREFIX          = /usr
WINDIR          = win32-binary
USRBIN          = $(PREFIX)/bin
USRSBIN         = $(PREFIX)/sbin
MANDIR          = $(PREFIX)/share/man/man8

OSYSTEM         = `uname -s`

CC              = $(USRBIN)/gcc
CFLAGS          = -Wall -Werror 
CFLAGS         += -O3 -mpreferred-stack-boundary=2
#CFLAGS         += -D__HAVE_LYRICS__

#LDFLAGS         += -static

INSTALL         = $(USRBIN)/install
INSTALL_OPTIONS = -c -p
INSTALL_PERMS   = -g wheel -o root -m 00700

RM              = $(BIN)/rm -f
MKDIR           = $(BIN)/mkdir

OBJECTS         = alpha2.o connect.o eng.o jmpaddr.o offset.o options.o payload.o randnops.o sendexp.o utils.o
PROGRAM         = eng

# Touch nothing before this point if you are not sure.
.c.o:
	@if [ $(OSYSTEM) != "Linux" ] && [ $(OSYSTEM) != "CYGWIN_NT-5.1" ]; then\
		echo "Sorry! The $(PROGRAM) was only tested under Linux and Gygwin32!";\
		exit 1;\
	fi
	$(CC) $(CFLAGS) -c $< -o $@

all: $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	@if [ $(OSYSTEM) == "Linux" ]; then\
		$(CC) $(LDFLAGS) -march=i686 -mcpu=i686 -m elf_i386 -o $@ $(OBJECTS);\
	elif [ $(OSYSTEM) == "CYGWIN_NT-5.1" ]; then\
		$(CC) $(LDFLAGS) -mtune=i386 -m i386pe -o $(WINDIR)/$@ $(OBJECTS);\
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
	for file in $(OBJECTS) $(PROGRAM) .*.swp core *.exe; do\
		if [ -f $$file ]; then\
			$(RM) $$file 1>&2 > /dev/null;\
		fi;\
	done
