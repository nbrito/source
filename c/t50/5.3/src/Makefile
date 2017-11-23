## 
#  $Id: Makefile,v 5.20 2011-03-09 11:01:01-03 nbrito Exp $
##

###########################################################################
# ___________._______________
# \__    ___/|   ____/\   _  \   T50: an Experimental Packet Injector Tool
#   |    |   |____  \ /  /_\  \                 Release 5.3
#   |    |   /       \\  \_/   \
#   |____|  /______  / \_____  /   Copyright (c) 2001-2011 Nelson Brito
#                  \/        \/             All Rights Reserved
#       
###########################################################################
# Author: Nelson Brito <nbrito@sekure.org>                                #
#                                                                         #
# Copyright (c) 2001-2011 Nelson Brito. All rights reserved worldwide.    #
#                                                                         #
# The following text was taken borrowed from Nmap License.                #
########################IMPORTANT T50 LICENSE TERMS########################
#                                                                         #
# T50 is program is free software;  you may redistribute and/or modify it #
# under the terms of the 'GNU General Public License' as published by the #
# Free  Software  Foundation;  Version  2  with  the  clarifications  and #
# exceptions described below.  This guarantees your right to use, modify, #
# and redistribute this software under certain conditions. If you wish to #
# embed T50 technology into  proprietary software,  please,  contact  the #
# author for an alternative license (contact nbrito@sekure.org).          #
#                                                                         #
# Note that the GPL places important restrictions on "derived works", yet #
# it  does  not provide a  detailed  definition of  that  term.  To avoid #
# misunderstandings, the author considers an application  to constitute a #
# "derivative work" for the purpose of this license if it does any of the #
# following:                                                              #
# 1 Integrates source code from T50.                                      #
# 2 Reads or includes T50 copyrighted data files, such: protocol modules, #
#   configuration files or libraries.                                     #
# 3 Integrates, includes or aggregates  T50 into a proprietary executable #
#   installer, such as those produced by InstallShield.                   #
# 4 Links to a library or executes a program that does any of the above.  #
#                                                                         #
# The term "T50" should be  taken to also include any portions or derived #
# works of T50.  This list is not exclusive,  but is meant to clarify the #
# author's interpretation  of  "derived works" with some common examples. #
# The author's interpretation applies only to T50 -- he doesn't speak for #
# other people's GPL works.                                               #
#                                                                         #
# If you have any questions about the GPL licensing restrictions on using #
# T50 in non-GPL works,  the author would be happy to help.  As mentioned #
# above, the author also offers alternative license to integrate T50 into #
# proprietary  applications  and  appliances.  These  licenses  generally #
# include  a  perpetual license as well as providing for priority support #
# and updates as well as helping to fund the continued development of T50 #
# technology.  Please email nbrito@sekure.org for further information.    #
#                                                                         #
# If  you  received these files  with  a  written  license  agreement  or #
# contract  stating   terms  other   than  the  terms  above,  then  that #
# alternative license agreement takes precedence over these comments.     #
#                                                                         #
# Source is provided to  this software because the author  believes users #
# have a right to know exactly what a program  is going to do before they #
# run it.  This also allows you to audit the software for security holes, #
# but none have been found so far.                                        #
#                                                                         #
# Source code also allows you to port T50 to new platforms, fix bugs, and #
# add new features and new protocol modules. You are highly encouraged to #
# send your changes to nbrito@sekure.org for possible  incorporation into #
# the main distribution. By sending these changes to Nelson Brito,  it is #
# assumed  that you are  offering the  T50 Project,  and its author,  the #
# unlimited,  non-exclusive right to reuse,  modify,  and  relicense  the #
# code.  T50 will always be available Open Source,  but this is important #
# because the inability to relicense code has caused devastating problems #
# for other Free Software projects  (such  as  KDE and NASM).  The author #
# also  occasionally  relicense  the  code  to third parties as discussed #
# above.  If  you wish to  specify  special license  conditions  of  your #
# contributions, just say so when you send them.                          #
#                                                                         #
# This  program  is distributed in the hope that it will  be useful,  but #
# WITHOUT  ANY  WARRANTY;    without   even   the   implied  warranty  of #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    #
# Please, refer to GNU General Public License v2.0 for further details at #
# http://www.gnu.org/licenses/gpl-2.0.html,  or  in the  LICENSE document #
# included with T50.                                                      #
###########################################################################


#
## GLOBAL PARAMETERS
##
## Global parameters used by GCC.
## Any new global parameter should be added in this section.
#
BIN             = /bin
PREFIX          = /usr
INCLUDE         = include
INCLUDES        = /usr/include
SOURCES         = .
OBJECTS         = objects
RELEASE         = release
MODULES         = modules
USRBIN          = $(PREFIX)/bin
USRSBIN         = $(PREFIX)/sbin
MANDIR          = $(PREFIX)/share/man/man8
CC              = $(USRBIN)/gcc
MAKEDEPEND      = $(USRBIN)/makedepend
RM              = $(BIN)/rm -f
MKDIR           = $(BIN)/mkdir
STRIP           = $(USRBIN)/strip
UPX             = $(USRBIN)/upx
OSYSTEM         = $(shell uname)
MAJOR_VERSION   = 5
MINOR_VERSION   = $(shell grep \$$Revision t50.c | awk  "{ print \$$7 }"  | awk -F"." "{ print \$$1 }")
T50_REVISION    = $(shell grep \$$Revision t50.c | awk  "{ print \$$7 }"  | awk -F"." "{ print \$$2 }")
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
CFLAGS         += -xc
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
CFLAGS         += -fstrict-aliasing
#CFLAGS         += -ftoplevel-reorder
#CFLAGS         += -funroll-loops
#CFLAGS         += -funroll-all-loops
CFLAGS         += -fomit-frame-pointer
#CFLAGS         += -fkeep-inline-functions
#CFLAGS         += -ftree-loop-optimize
#CFLAGS         += -fbranch-target-load-optimize
#CFLAGS         += -foptimize-register-move
#CFLAGS         += -lmpi
ifeq ($(ARCH),x86_64)
	CFLAGS         += -m64
#	CFLAGS         += -mpc64
endif
ifeq ($(ARCH),i386)
	CFLAGS         += -m32
	CFLAGS         += -mpc32
endif
#CFLAGS         += -msahf
CFLAGS         += -march=native
CFLAGS         += -mtune=native


#
## GLOBAL DEFINE FLAGS
##
## Global define flags used by GCC.
## Any new define flag should be added in this section.
#
# Setting DEBUG.
#DFLAGS         += -D__HAVE_DEBUG__
#
# Setting USAGE.
DFLAGS         += -D__HAVE_USAGE__
#
# Setting THE REAL T50 POWER.
DFLAGS         += -D__HAVE_T50__
#
# Setting TURBO.
DFLAGS         += -D__HAVE_TURBO__
#
# Setting CIDR.
DFLAGS         += -D__HAVE_CIDR__
#
# Setting RESTRICTION ( __HAVE_RESTRICTION__ = __HAVE_LIMITATION__ + __HAVE_EXPIRATION__).
#DFLAGS         += -D__HAVE_RESTRICTION__
#
# Setting RFC 1700, 1918 and 3330 Compliance.
DFLAGS         += -D__HAVE_LIMITATION__

# Setting SUSv2 header exposing (Patch by Fernando Mercês <fernando@mentebinaria.com.br>)
DFLAGS         += -D_XOPEN_SOURCE=500
DFLAGS         += -D_GNU_SOURCE
#
# Setting EXPIRATION date.
#DFLAGS         += -D__HAVE_EXPIRATION__
#DFLAGS         += -DEXPIRATION_FIRST_DAY=1
#DFLAGS         += -DEXPIRATION_LAST_DAY=30
#DFLAGS         += -DEXPIRATION_MONTH=3
#DFLAGS         += -DEXPIRATION_YEAR=2011
#
# Setting VERSION.
DFLAGS         += -DMAJOR_VERSION=\"$(MAJOR_VERSION)\"
DFLAGS         += -DMINOR_VERSION=\"$(MINOR_VERSION)\"
DFLAGS         += -DT50_REVISION=\"$(T50_REVISION)\"
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
LFLAGS         += -m elf_$(ARCH)
# LINKING MATH LIB - IF '__HAVE_CIDR__' THEN enable ELSE disable.
LFLAGS         += -lm
#
# CAUTION: Do not enable '-s' and '-static' on the same time.
LFLAGS         += -s
#LFLAGS         += -static
LFLAGS         += -o


#
## GLOBAL UPX FLAGS
##
## Global packer flags used by UPX.
## Any new packer flag should be added in this section.
UFLAGS         += -9
UFLAGS         += --best
UFLAGS         += -f
UFLAGS         += -q


#
## GLOBAL INSTALLER FLAGS
##
## Global installer flags used by INSTALL.
## Any new installer flag should be added in this section.
#
INSTALL        += $(USRBIN)/install
#
# Setting install options.
IFLAGS         += -c
IFLAGS         += -p
#
# Setting install permissions.
IPERMS         += -g bin
IPERMS         += -o root
#
# The following permissions requires 'sudo'.
IPERMS         += -m 00700
#
# The following permissions does not require 'sudo'.
#IPERMS         += -m 04755


#
## GLOBAL PROGRAM
#
PROGRAM         = t50


# XXX WARNING XXX WARNING XXX WARNING XXX
##
## Touch nothing beyond this point!!!
##
# XXX WARNING XXX WARNING XXX WARNING XXX
.SUFFIXES: .c

$(OBJECTS)/%.o: $(SOURCES)/%.c
	$(CC) $(CFLAGS) -c $< $(DFLAGS) -o $@
$(OBJECTS)/%.o: $(MODULES)/%.c
	$(CC) $(CFLAGS) -c $< $(DFLAGS) -o $@

MAIN_SOURCES    := $(wildcard $(SOURCES)/*.c)
PROTO_SOURCES   := $(wildcard $(MODULES)/*.c)

SOURCE = $(MAIN_SOURCES) $(PROTO_SOURCES)
OBJECT = $(addprefix $(OBJECTS)/, $(notdir $(addsuffix .o, $(basename $(SOURCE)))))

$(RELEASE)/$(PROGRAM): $(OBJECT)
	$(CC) $(LFLAGS) $@ $(OBJECT)
	@if [ -f $(STRIP) ] && [ -e $(STRIP) ]; then\
		$(STRIP) -s $@ 1>&2 > /dev/null;\
	fi
	@if [ -f $(UPX) ] && [ -e $(UPX) ]; then\
		$(UPX) $(UFLAGS) $@ 1>&2 > /dev/null;\
	fi

depend:
	$(MAKEDEPEND) $(DFLAGS) -Y $(SOURCE)

install: $(RELEASE)/$(PROGRAM)
	@if [ ! -d $(USRSBIN) ]; then\
		$(MKDIR) $(USRSBIN);\
	fi
	$(INSTALL) $(IFLAGS) $< $(IPERMS) $(USRSBIN)

uninstall: $(RELEASE)/$(PROGRAM)
	@if [ -f $(USRSBIN)/$(PROGRAM) ] && [ -e $(USRSBIN)/$(PROGRAM) ]; then\
		 $(RM) $(USRSBIN)/$(PROGRAM);\
	fi
	
clean:
	for file in $(OBJECT) $(RELEASE)/$(PROGRAM) *~ .*.swp core; do\
		if [ -f $$file ]; then\
			$(RM) $$file 1>&2 > /dev/null;\
		fi;\
	done
