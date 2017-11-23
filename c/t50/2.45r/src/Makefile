##
# $Id: Makefile,v 3.24 2010-11-27 14:48:12-02 nbrito Exp $
##

## ------------------x------------------x------------------x------------------
## Author: Nelson Brito <nbrito[at]sekure[dot]org>
##
## Copyright (c) 2001-2010 Nelson Brito. All rights reserved worldwide.
##
## This software and its codes may be provided as  source code but IS NOT
## LICENSED under the GPL or any other common Open Source licenses.
## ------------------x------------------x------------------x------------------
##
##                  T50: an Experimental Packet Injector Tool
##                                Release 2.45
##
##                    Copyright (c) 2001-2010 Nelson Brito
##                             All Rights Reserved
##
##   T50 IS AN EXPERIMENTAL SOFTWARE  AND IS KNOWN TO CAUSE SERIOUS DAMAGES
##   IN COMPUTER SYSTEMS, SOME OF WHICH MAY BE IN VIOLATION OF FEDERAL LAW,
##   INCLUDING  THE  COMPUTER  FRAUD  AND  ABUSE  ACT  AND  OTHER  RELEVANT
##   PROVISIONS OF FEDERAL CIVIL AND CRIMINAL LAW.  VIOLATION WILL / CAN BE
##   SUBJECT  TO  CIVIL  AND  CRIMINAL  PENALTIES  INCLUDING CIVIL MONETARY
##   PENALTIES.
##
##   THIS SOFTWARE  IS PROVIDED  ``AS IS'',  WITHOUT  WARRANTY OF ANY KIND,
##   EXPRESS  OR  IMPLIED, INCLUDING BUT NOT  LIMITED  TO THE WARRANTIES OF
##   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
##   IN NO  EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS  BE LIABLE FOR ANY
##   CLAIM, DAMAGES  OR OTHER LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,
##   TORT  OR OTHERWISE,  ARISING FROM,  OUT OF  OR IN CONNECTION  WITH THE
##   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
##
## ------------------x------------------x------------------x------------------

#
## GLOBAL PARAMETERS
##
## Global parameters used by GCC.
## Any new global parameter should be added in this section.
#
BIN             = /bin/
PREFIX          = /usr/
INCLUDE         = ./include/
INCLUDES        = /usr/include/
OBJECT          = ./objects/
RELEASE         = ./release/
USRBIN          = $(PREFIX)/bin
USRSBIN         = $(PREFIX)/sbin
MANDIR          = $(PREFIX)/share/man/man8
RM              = $(BIN)/rm -f
MKDIR           = $(BIN)/mkdir
STRIP           = $(USRBIN)/strip
UPX             = $(USRBIN)/upx
OSYSTEM         = $(shell uname)
MAJOR_VERSION   = 2
MINOR_VERSION   = 45
BUILD_VERSION   = $(shell date +%y%m%d)
BUILD_PLATFORM  = generic
SUBARCH        := $(shell uname -m | sed -e s/i.86/i386/)
ARCH	       ?= $(SUBARCH)
BUILD_PLATFORM := $(ARCH)
ifeq ($(ARCH),i386)
	BUILD_PLATFORM := 32-bit
endif
ifeq ($(ARCH),x86_64)
	BUILD_PLATFORM := 64-bit
endif
REGISTERED_USER = $(shell whoami)
REGISTERED_FQDN = $(shell hostname)


#
## GLOBAL COMPILER FLAGS
##
## Global compiler flags used by GCC.
## Any new compiler flag should be added in this section.
#
# Setting the language C.
CC              = $(USRBIN)/gcc
CFLAGS          = -xc
#
# Setting warning messages.
CFLAGS         += -Wall
CFLAGS         += -Wextra
CFLAGS         += -Werror
CFLAGS         += -Wformat
CFLAGS         += -Wformat-nonliteral
CFLAGS         += -Wformat-security
CFLAGS         += -Wformat-y2k
CFLAGS         += -Wimplicit
CFLAGS         += -Winline
CFLAGS         += -Waddress
CFLAGS         += -Warray-bounds
#
# Tuning parameters to better optimization.
CFLAGS         += -O3
ifeq ($(ARCH),x86_64)
	CFLAGS         += -ffast-math
	CFLAGS         += -fstack-protector-all
endif
CFLAGS         += -ftoplevel-reorder
CFLAGS         += -funroll-loops
CFLAGS         += -funroll-all-loops
CFLAGS         += -fomit-frame-pointer
CFLAGS         += -fkeep-inline-functions
CFLAGS         += -ftree-loop-optimize
CFLAGS         += -fbranch-target-load-optimize
CFLAGS         += -foptimize-register-move
CFLAGS         += -lmpi
ifeq ($(ARCH),x86_64)
	CFLAGS         += -m64
	CFLAGS         += -mpc64
endif
ifeq ($(ARCH),i386)
	CFLAGS         += -m32
	CFLAGS         += -mpc32
endif
CFLAGS         += -msahf
CFLAGS         += -march=native
CFLAGS         += -mtune=native


#
## GLOBAL DEFINE FLAGS
##
## Global define flags used by GCC.
## Any new define flag should be added in this section.
#
# Setting DEBUG.
#DFLAGS          = -D__HAVE_DEBUG__
#
# Setting USAGE.
#DFLAGS         += -D__HAVE_USAGE__
#
# Setting THE REAL T50 POWER.
#DFLAGS         += -D__HAVE_T50__
#
# Setting TURBO.
#DFLAGS         += -D__HAVE_TURBO__
#
# Setting RESTRICTION ( __HAVE_RESTRICTION__ = __HAVE_LIMITATION__ + __HAVE_EXPIRATION__).
#DFLAGS         += -D__HAVE_RESTRICTION__
#
# Setting RFC 1918 LIMITATION.
DFLAGS         += -D__HAVE_LIMITATION__
#
# Setting EXPIRATION date.
#DFLAGS         += -D__HAVE_EXPIRATION__
#DFLAGS         += -DEXPIRATION_FIRST_DAY=1
#DFLAGS         += -DEXPIRATION_LAST_DAY=30
#DFLAGS         += -DEXPIRATION_MONTH=11
#DFLAGS         += -DEXPIRATION_YEAR=2010
#
# Setting VERSION.
DFLAGS         += -DMAJOR_VERSION=\"$(MAJOR_VERSION)\"
DFLAGS         += -DMINOR_VERSION=\"$(MINOR_VERSION)\"
DFLAGS         += -DBUILD_VERSION=\"$(BUILD_VERSION)\"
DFLAGS         += -DBUILD_PLATFORM=\"$(BUILD_PLATFORM)\"
#
# Setting USER and FQDN.
DFLAGS         += -DREGISTERED_USER=\"$(REGISTERED_USER)\"
DFLAGS         += -DREGISTERED_FQDN=\"$(REGISTERED_FQDN)\"
#
# Setting INCLUDE.
DFLAGS         += -I$(INCLUDE)
DFLAGS         += -I$(INCLUDES)


#
## GLOBAL LINKER FLAGS
##
## Global linker flags used by GCC.
## Any new linker flag should be added in this section.
#
# Tuning parameters to better performance in linkage process.
LFLAGS          = -m elf_$(ARCH)
#
# CAUTION: Do not enable '-s' and '-static' on the same time.
LFLAGS         += -s
#LFLAGS         += -static
LFLAGS         += -o


#
## GLOBAL INSTALLER FLAGS
##
## Global installer flags used by INSTALL.
## Any new installer flag should be added in this section.
#
INSTALL         = $(USRBIN)/install
#
# Setting install options.
IFLAGS          = -c
IFLAGS         += -p
#
# Setting install permissions.
IPERMS          = -g bin
IPERMS         += -o root
IPERMS         += -m 00700


#
## GLOBAL SOURCES
##
## Global sources used by PROGRAM.
## Any new source should be added in this section.
#
SOURCES         = check.o
SOURCES        += cksum.o
SOURCES        += config.o
SOURCES        += icmp.o
SOURCES        += igmp.o
SOURCES        += resolv.o
SOURCES        += sock.o
SOURCES        += t50.o
SOURCES        += tcp.o
SOURCES        += udp.o
SOURCES        += usage.o          


#
## GLOBAL OBJECTS
##
## Global objects used by PROGRAM.
## Any new object should be added in this section.
#
OBJECTS         = $(OBJECT)/check.o
OBJECTS        += $(OBJECT)/cksum.o
OBJECTS        += $(OBJECT)/config.o
OBJECTS        += $(OBJECT)/icmp.o
OBJECTS        += $(OBJECT)/igmp.o
OBJECTS        += $(OBJECT)/resolv.o
OBJECTS        += $(OBJECT)/sock.o
OBJECTS        += $(OBJECT)/t50.o
OBJECTS        += $(OBJECT)/tcp.o
OBJECTS        += $(OBJECT)/udp.o
OBJECTS        += $(OBJECT)/usage.o


#
## GLOBAL PROGRAM
#
PROGRAM         = $(RELEASE)/t50


# XXX WARNING XXX WARNING XXX WARNING XXX
##
## Touch nothing beyond this point!!!
##
# XXX WARNING XXX WARNING XXX WARNING XXX
.c.o:
	@if [ $(OSYSTEM) != "Linux" ]; then\
		echo "Sorry! The $(PROGRAM) was only tested under Linux!";\
		exit 1;\
	fi
	$(CC) $(CFLAGS) -c $< $(DFLAGS) -o $(OBJECT)/$@

all: $(PROGRAM)

$(PROGRAM): $(SOURCES)

	$(CC) $(LFLAGS) $@ $(OBJECTS)
	@if [ -f $(STRIP) ] && [ -e $(STRIP) ]; then\
		$(STRIP) -s $@ 1>&2 > /dev/null;\
	fi
	@if [ -f $(UPX) ] && [ -e $(UPX) ]; then\
		$(UPX) --best --ultra-brute -q $@ 1>&2 > /dev/null;\
	fi

install: $(PROGRAM)
	@if [ ! -d $(USRSBIN) ]; then\
		$(MKDIR) $(USRSBIN);\
	fi
	$(INSTALL) $(IFLAGS) $< $(IPERMS) $(USRSBIN)

uninstall: $(PROGRAM)
	@if [ -f $(USRSBIN)/$(PROGRAM) ] && [ -e $(USRSBIN)/$(PROGRAM) ]; then\
		 $(RM) $(USRSBIN)/$(PROGRAM);\
	fi
	
clean:
	for file in $(OBJECTS) $(PROGRAM) *~ .*.swp core; do\
		if [ -f $$file ]; then\
			$(RM) $$file 1>&2 > /dev/null;\
		fi;\
	done
