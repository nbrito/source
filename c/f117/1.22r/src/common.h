/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the F117 Private Tool by Nelson Brito.

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
#define __COMMON_H 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: common.h,v 1.1 2008-09-12 15:36:14-03 nbrito Exp $ */
#define __MAJOR_VERSION "1" 
#define __MINOR_VERSION "22"

#ifndef __linux__
#error "Sorry! The f117 program was only tested under Linux!"
#endif  /* __linux__ */

#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

__BEGIN_DECLS

/* XXX - Do not remove, it will be used in a near future. I hope. */
#if     __GLIBC_PREREQ(2, 1)
/* XXX - Internal declarations. */

#include <netpacket/packet.h>
#include <net/ethernet.h>

#else   /* __GLIBC_PREREQ(2, 1) */
/* XXX - External declarations. */

#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#endif  /* __GLIBC_PREREQ(2, 1) */

/* Using macro instead of function. This is a kind of copyright. ;-) */
#define nb(c, t) do {\
			fprintf(stdout,"%c",*c++);fflush(stdout);\
			usleep(t);\
		} while(*c)

/* Was RAND_MAX defined? */
#ifndef RAND_MAX
#define RAND_MAX 2147483647
#endif  /* RAND_MAX */

/* Defining the POSIX standards types in case of need.
   IMHO, it will help in portability. */
/* 8 bits signed.    */
#ifndef int8_t
#define int8_t signed char
#endif  /* int8_t */

/* 8 bits unsigned.  */
#ifndef u_int8_t
#define u_int8_t unsigned char
#endif  /* u_int8_t */

/* 16 bits signed.   */
#ifndef int16_t
#define int16_t signed short
#endif  /* int16_t */

/* 16 bits unsigned. */
#ifndef u_int16_t
#define u_int16_t unsigned short
#endif  /* int16_t */

/* 32 bits signed.   */
#ifndef int32_t
#define int32_t signed int
#endif  /* int32_t */

/* 32 bits unsigned. */
#ifndef u_int32_t
#define u_int32_t unsigned int
#endif  /* u_int32_t */

/* 32 bits unsigned. */
#ifndef in_addr_t
#define in_addr_t u_int32_t
#endif  /* in_addr_t */

/* Pseudo header for packet's checking sum routine. */
struct psdhdr{
	in_addr_t saddr;    /* source address (32 bits)      */
	in_addr_t daddr;    /* destination address (32 bits) */
	u_int8_t  zero;     /* must be zero (8 bits)         */
	u_int8_t  protocol; /* protocol (8 bits)             */
	u_int16_t len;      /* header length (16 bits)       */
};

/* Defining: Internet address ANY; Macro for random address routine;
   TCP/IP port ANY; Macro for random port routine. */
#ifndef INADDR_ANY
#define INADDR_ANY ((in_addr_t) 0x00000000)
#endif  /* INADDR_ANY */

#ifndef INADDR_RND
#define INADDR_RND(addr)\
		(addr == INADDR_ANY ?\
		((rand() & 0xffffffff) << 31) + (rand() & 0xffffffff) :\
		(in_addr_t) addr)
#endif  /* INADDR_RND */

#ifndef IPPORT_ANY
#define IPPORT_ANY ((u_int16_t) 0x0000)
#endif  /* IPPORT_ANY */

#ifndef IPPORT_DNS
#define IPPORT_DNS 53
#endif  /* IPPORT_DNS */

#ifndef IPPORT_RND
#define IPPORT_RND(port)\
		(port == IPPORT_ANY ?\
		((rand() & 0xffff) << 16) + (rand() & 0xffff) :\
		port)
#endif  /* IPPORT_RND */

/* Defining headers' sizes. */
#ifndef IPHDR_SIZE
#define IPHDR_SIZE   sizeof(struct iphdr)
#endif  /* IPHDR_SIZE */

#ifndef ICMPHDR_SIZE
#define ICMPHDR_SIZE sizeof(struct icmphdr)
#endif  /* ICMPHDR_SIZE */

#ifndef UDPHDR_SIZE
#define UDPHDR_SIZE sizeof(struct udphdr)
#endif  /* UDPHDR_SIZE */

#ifndef TCPHDR_SIZE
#define TCPHDR_SIZE sizeof(struct tcphdr)
#endif  /* TCPHDR_SIZE */

#ifndef PSDHDR_SIZE
#define PSDHDR_SIZE sizeof(struct psdhdr)
#endif  /* PSDHDR_SIZE */

/* Was IPVERSION defined? */
#ifndef IPVERSION
#define IPVSERION 4
#endif  /* IPVERSION */

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
	/* General header options (UDP & TCP).                   */
	u_int16_t source ;       /* general source port          */
	u_int16_t dest;          /* general destination port     */
	u_int16_t fin;           /* end of data flag             */
	u_int16_t syn;           /* synchronize ISN flag         */
	u_int16_t rst;           /* reset connection flag        */
	u_int16_t psh;           /* push flag                    */
	u_int16_t ack;           /* acknowledgment # valid flag  */
	u_int16_t urg;           /* urgent pointer valid flag    */
};

/* Prototype for usage help message. */
extern void usage(int8_t *, int8_t *, int8_t *); 

/* Prototype for name and IP address resolving routine. */
extern const in_addr_t resolv(const u_int8_t *);

/* Prototype for options processing routine. */
extern const struct options process_options(int, char **);

/* Prototype for raw packet sending routine. */
extern const int32_t sendraw(register int32_t, struct options);

/* Prototype for packet's check summing routine. */
extern const u_int16_t in_cksum(register u_int16_t *, register int32_t);

__END_DECLS

#endif  /* __COMMON_H */
