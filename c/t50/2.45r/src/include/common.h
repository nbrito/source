/* 
 * $Id: common.h,v 3.12 2010-11-27 14:48:52-02 nbrito Exp $
 */

/* ------------------x------------------x------------------x------------------
 * Author: Nelson Brito <nbrito[at]sekure[dot]org>
 *
 * Copyright (c) 2001-2010 Nelson Brito. All rights reserved worldwide.
 *
 * This software and its codes may be provided as  source code but IS NOT
 * LICENSED under the GPL or any other common Open Source licenses.
 * ------------------x------------------x------------------x------------------

                    T50: an Experimental Packet Injector Tool
                                  Release 2.45

                      Copyright (c) 2001-2010 Nelson Brito
                               All Rights Reserved

     T50 IS AN EXPERIMENTAL SOFTWARE  AND IS KNOWN TO CAUSE SERIOUS DAMAGES
     IN COMPUTER SYSTEMS, SOME OF WHICH MAY BE IN VIOLATION OF FEDERAL LAW,
     INCLUDING  THE  COMPUTER  FRAUD  AND  ABUSE  ACT  AND  OTHER  RELEVANT
     PROVISIONS OF FEDERAL CIVIL AND CRIMINAL LAW.  VIOLATION WILL / CAN BE
     SUBJECT  TO  CIVIL  AND  CRIMINAL  PENALTIES  INCLUDING CIVIL MONETARY
     PENALTIES.

     THIS SOFTWARE  IS PROVIDED  ``AS IS'',  WITHOUT  WARRANTY OF ANY KIND,
     EXPRESS  OR  IMPLIED, INCLUDING BUT NOT  LIMITED  TO THE WARRANTIES OF
     MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
     IN NO  EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS  BE LIABLE FOR ANY
     CLAIM, DAMAGES  OR OTHER LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,
     TORT  OR OTHERWISE,  ARISING FROM,  OUT OF  OR IN CONNECTION  WITH THE
     SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
   
   ------------------x------------------x------------------x------------------ */
#ifndef __COMMON_H
#define __COMMON_H 1
#if     !(linux) || !(__linux__)
#	error "Sorry! The t50 was only tested under Linux!"
#endif  /* __linux__ */
#ifdef  __USE_BSD
#	warning "Sorry! The t50 is disabling __USE_BSD!"
#	undef  __USE_BSD
#endif  /* __USE_BSD */
#ifdef  __FAVOR_BSD
#	warning "Sorry! The t50 is disabling __FAVOR_BSD!"
#	undef  __FAVOR_BSD
#endif  /* __FAVOR_BSD */


/* GLOBAL HEADERS/INCLUDES

   Global headers/includes used by code.
   Any new global headers/includes should be added in this section. */
#include <time.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
extern int    optind;
extern char * optarg;
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
/* XXX WARNING XXX
   Do not remove, it will be used in a near future. I hope!!! ;) 
   XXX WARNING XXX */
#if     __GLIBC_PREREQ(2, 1)
/* XXX WARNING XXX
   Internal declarations.
   XXX WARNING XXX */
#	include <net/if.h>            /* Network Interface Card info   */
#	include <net/if_arp.h>        /* ARP Header                    */
#	include <net/ethernet.h>      /* Ethernet Header               */
#	include <netpacket/packet.h>  /* L2 protocols                  */
#else   /* __GLIBC_PREREQ(2, 1) */
/* XXX WARNING XXX
   External declarations.
   XXX WARNING XXX */
#	include <asm/types.h>
#	include <linux/if.h>          /* Network Interface Card info   */
#	include <linux/if_arp.h>      /* ARP Header                    */
#	include <linux/if_ether.h>    /* Ethernet Header               */
#	include <linux/if_packet.h>   /* L2 Protocols                  */
#endif  /* __GLIBC_PREREQ(2, 1) */

#ifdef __cplusplus
extern "C" {
#endif

__BEGIN_DECLS

/* GLOBAL VERSION

   Global version used by code.
   Any new global version should be added in this section. */
#ifndef MAJOR_VERSION
/* The MAXIMUM SPEED for T50 Sukhoi PAK FA is: Mach 2.45 (1,615 mph, 2,600 km/h). */
#	define MAJOR_VERSION            __STRING(2)
#endif  /* MAJOR_VERSION */
#ifndef MINOR_VERSION
#	define MINOR_VERSION            __STRING(45)
#endif  /* MINOR_VERSION */
#ifndef BUILD_VERSION
#	define BUILD_VERSION            __STRING(100909)
#endif  /* BUILD_VERSION */
#ifndef BUILD_PLATFORM
#	if     __WORDSIZE == 32
#		define BUILD_PLATFORM   __STRING(32-bit)
#	elif   __WORDSIZE == 64
#		define BUILD_PLATFORM   __STRING(64-bit)
#	else   /* __WORDSIZE */
#		define BUILD_PLATFORM   __STRING(generic)
#	endif  /* __WORDSIZE */
#endif  /* BUILD_PLATFORM */
#ifndef REGISTERED_USER
#	define REGISTERED_USER          __STRING(unknown)
#endif  /* REGISTERED_USER */
#ifndef REGISTERED_FQDN
#	define REGISTERED_FQDN          __STRING(unknown.domain)
#endif  /* REGISTERED_FQDN */
#ifdef  __HAVE_RESTRICTION__
#	define __HAVE_EXPIRATION__      1
#	define __HAVE_LIMITATION__      1
#endif  /* __HAVE_RESTRICTION__ */
#ifdef  __HAVE_EXPIRATION__
#	if     !(EXPIRATION_FIRST_DAY)
#		define EXPIRATION_FIRST_DAY   1
#	elif   (EXPIRATION_FIRST_DAY < 1)
#		error "Sorry! The t50 EXPIRATION_FIRST_DAY cannot be less than 1!"
#	endif  /* (EXPIRATION_FIRST_DAY) */
#	if     !(EXPIRATION_LAST_DAY)
#		define EXPIRATION_LAST_DAY   30
#	elif   (EXPIRATION_LAST_DAY > 30)
#		error "Sorry! The t50 EXPIRATION_LAST_DAY cannot be greater than 30!"
#	endif  /* (EXPIRATION_LAST_DAY) */
#	if     !(EXPIRATION_MONTH)
#		define EXPIRATION_MONTH 6
#	elif   (EXPIRATION_MONTH > 12)
#		error "Sorry! The t50 EXPIRATION_MONTH cannot be greater than 12!"
#	endif  /* (EXPIRATION_MONTH) */
#	if     (EXPIRATION_FIRST_DAY > EXPIRATION_LAST_DAY)
#		error "Sorry! The t50 EXPIRATION_FIRST_DAY cannot be greater than EXPIRATION_LAST_DAY!"
#	endif  /* (EXPIRATION_FIRST_DAY > EXPIRATION_LAST_DAY) */
#	if     !(EXPIRATION_YEAR)
#		define EXPIRATION_YEAR  2010
#	endif  /* (EXPIRATION_YEAR) */
#endif  /* __HAVE_EXPIRATION__ */

/* GLOBAL DEFINES

   Global defines used by code.
   Any new global defines should be added in this section. */
#ifdef  RAND_MAX
/* Disabling warning.
#	warning "Sorry! The t50 is disabling RAND_MAX!" */
#	undef  RAND_MAX
#	define RAND_MAX 2147483647
#else   /* RAND_MAX */
#	define RAND_MAX 2147483647
#endif  /* RAND_MAX */
#ifdef  __HAVE_T50__
#	ifndef T50_THRESHOLD_MIN
#		define T50_THRESHOLD_MIN 4
#	else   /* T50_THRESHOLD_MIN */
#		warning "Sorry! The t50 is disabling T50_THRESHOLD_MIN!"
#		undef  T50_THRESHOLD_MIN
#		define T50_THRESHOLD_MIN 4
#	endif  /* T50_THRESHOLD_MIN */
#endif  /* __HAVE_T50__ */
#ifdef  int8_t
#	warning "Sorry! The t50 is disabling int8_t!"
#	undef  int8_t
#	define int8_t char
#else     /* int8_t */
#	define int8_t char
#endif  /* int8_t */
#ifdef  u_int8_t
#	warning "Sorry! The t50 is disabling u_int8_t!"
#	undef  u_int8_t
#	define u_int8_t unsigned char
#else   /* u_int8_t */
#	define u_int8_t unsigned char
#endif  /* u_int8_t */
#ifdef  int16_t
#	warning "Sorry! The t50 is disabling int16_t!"
#	undef  int16_t
#	define int16_t short
#else   /* int16_t */
#	define int16_t short
#endif  /* int16_t */
#ifdef  u_int16_t
#	warning "Sorry! The t50 is disabling u_int16_t!"
#	undef u_int16_t
#	define u_int16_t unsigned short
#else   /* u_int16_t */
#	define u_int16_t unsigned short
#endif  /* u_int16_t */
#ifdef  int32_t
#	warning "Sorry! The t50 is disabling int32_t!"
#	undef  int32_t
#	define int32_t int
#else   /* int32_t */
#	define int32_t int
#endif  /* int32_t */
#ifdef  u_int32_t
#	warning "Sorry! The t50 is disabling u_int32_t!"
#	undef  u_int32_t
#	define u_int32_t unsigned int
#else   /* u_int32_t */
#	define u_int32_t unsigned int
#endif  /* u_int32_t */
#ifdef  in_addr_t
#	warning "Sorry! The t50 is disabling in_addr_t!"
#	undef  in_addr_t
#	define in_addr_t u_int32_t
#else   /* in_addr_t */
#	define in_addr_t u_int32_t
#endif  /* in_addr_t */
#ifdef  socket_t
#	warning "Sorry! The t50 is disabling socket_t!"
#	undef  socket_t
#	define socket_t int32_t
#else   /* socket_t */
#	define socket_t int32_t
#endif  /* socket_t */
#ifdef  INADDR_ANY
/* Disabling warning.
#	warning "Sorry! The t50 is disabling INADDR_ANY!" */
#	undef  INADDR_ANY
#	define INADDR_ANY ((in_addr_t) 0x00000000)
#else   /* INADDR_ANY */
#	define INADDR_ANY ((in_addr_t) 0x00000000)
#endif  /* INADDR_ANY */
#ifdef  IPPORT_ANY
#	warning "Sorry! The t50 is disabling IPPORT_ANY!"
#	undef  IPPORT_ANY
#	define IPPORT_ANY ((u_int16_t) 0x0000)
#else   /* IPPORT_ANY */
#	define IPPORT_ANY ((u_int16_t) 0x0000)
#endif  /* IPPORT_ANY */
#ifdef  IPPROTO_T50
#	warning "Sorry! The t50 is disabling IPPROTO_T50!"
#	undef  IPPROTO_T50
#	define IPPROTO_T50 69
#else   /* IPPROTO_T50 */
#	define IPPROTO_T50 69
#endif  /* IPPROTO_T50 */
#ifdef  IPVERSION
/* Disabling warning.
#	warning "Sorry! The t50 is disabling IPVERSION!" */
#	undef  IPVSERION
#	define IPVSERION 4
#else   /* IPVERSION */
#	define IPVSERION 4
#endif  /* IPVERSION */
#ifdef  IP_MF
#	warning "Sorry! The t50 is disabling IP_MF!"
#	undef  IP_MF
#	define IP_MF 0x2000
#else   /* IP_MF */
#	define IP_MF 0x2000
#endif  /* IP_MF */
#ifdef  IP_DF
#	warning "Sorry! The t50 is disabling IP_MF!"
#	undef  IP_DF
#	define IP_DF 0x4000
#else   /* IP_DF */
#	define IP_DF 0x4000
#endif  /* IP_DF */


/* GLOBAL VARIABLES

   Global variables used by code.
   Any new global variable should be added in this section. */
#if     (T50_C__) || (CONFIG_C__)
static int8_t * program       = "t50";
#	ifdef  T50_C__
static int8_t * months[]      = { 
				"Jan",
				"Feb",
				"Mar",
				"Apr",
				"May",
				"Jun",
				"Jul",
				"Aug",
				"Sep",
				"Oct",
				"Nov",
				"Dez",
				NULL 
};
#	endif  /* T50_C__ */
#	ifdef  CONFIG_C__
static int8_t * author        = "Nelson Brito";
static int8_t * email         = "nbrito[at]sekure[dot]org";
static int8_t * copyright     = "/* ------------------x------------------x------------------x------------------\n"
				" * Author: Nelson Brito <nbrito[at]sekure[dot]org>\n"
				" *\n"
				" * Copyright (c) 2001-2010 Nelson Brito. All rights reserved worldwide.\n"
				" *\n"
				"  * This software and its codes may be provided as  source code but IS NOT"
				" * LICENSED under the GPL or any other common Open Source licenses.\n"
				" * ------------------x------------------x------------------x------------------\n\n"
				"                    T50: an Experimental Packet Injector Tool\n"
				"                                  Release 2.45\n\n"
				"                      Copyright (c) 2001-2010 Nelson Brito\n"
				"                               All Rights Reserved\n\n"
				"     T50 IS AN EXPERIMENTAL SOFTWARE  AND IS KNOWN TO CAUSE SERIOUS DAMAGES\n"
				"     IN COMPUTER SYSTEMS, SOME OF WHICH MAY BE IN VIOLATION OF FEDERAL LAW,\n"
				"     INCLUDING  THE  COMPUTER  FRAUD  AND  ABUSE  ACT  AND  OTHER  RELEVANT\n"
				"     PROVISIONS OF FEDERAL CIVIL AND CRIMINAL LAW.  VIOLATION WILL / CAN BE\n"
				"     SUBJECT  TO  CIVIL  AND  CRIMINAL  PENALTIES  INCLUDING CIVIL MONETARY\n"
				"     PENALTIES.\n\n"
				"     THIS SOFTWARE  IS PROVIDED  ``AS IS'',  WITHOUT  WARRANTY OF ANY KIND,\n"
				"     EXPRESS  OR  IMPLIED, INCLUDING BUT NOT  LIMITED  TO THE WARRANTIES OF\n"
				"     MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.\n"
				"     IN NO  EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS  BE LIABLE FOR ANY\n"
				"     CLAIM, DAMAGES  OR OTHER LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,\n"
				"     TORT  OR OTHERWISE,  ARISING FROM,  OUT OF  OR IN CONNECTION  WITH THE\n"
				"     SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n\n"
				"   ------------------x------------------x------------------x------------------\n"
				" */\n";
#	endif  /* CONFIG_C__ */
#endif  /* (T50_C__) || (CONFIG_C__) */
#if     ((CHECK_C__) && (__HAVE_T50__)) || (CONFIG_C__)
static int8_t   * protocols[] = { 
				"ICMP",
				"IGMP",
				"TCP",
				"UDP",
#	ifdef  __HAVE_T50__
				"T50",
#	endif  /* __HAVE_T50__ */
				NULL
};
#endif  /* (CHECK_C__) || (CONFIG_C__) */
enum {
				OPTION_ICMP  = 0,
				OPTION_IGMP  = 1,
				OPTION_TCP   = 2,
				OPTION_UDP   = 3,
#ifdef  __HAVE_T50__
				OPTION_T50   = 4,
#endif  /* __HAVE_T50__ */
};


/* COMMON STRUCTURES

   Common structures used by code.
   Any new common structure should be added in this section. */
struct psdhdr{
	/* For further information check RFC 793 & RFC 768.                 */
 	in_addr_t saddr;                  /* source address (32 bits)       */
	in_addr_t daddr;                  /* destination address (32 bits)  */
	u_int8_t  zero;                   /* must be zero (8 bits)          */
	u_int8_t  protocol;               /* protocol (8 bits)              */
	u_int16_t len;                    /* header length (16 bits)        */
};
struct config_options{
	/* XXX COMMON OPTIONS XXX                                           */
	u_int32_t  threshold;             /* amount of packets              */
	u_int32_t  flood;                 /* flood                          */
	u_int32_t  bogus_csum;            /* bogus packet checksum          */
#ifdef  __HAVE_TURBO__
	u_int32_t  turbo;                 /* duplicate the attack           */
#endif  /* __HAVE_TURBO__ */
	u_int32_t  copyright;             /* display copyright statement    */
	/* XXX IP HEADER OPTIONS XXX                                        */
	struct{
		u_int8_t  tos;            /* type of service                */
		u_int16_t id;             /* identification                 */
		u_int16_t frag_off;       /* fragmentation offset           */
		u_int8_t  ttl;            /* time to live                   */
		u_int8_t  protocol;       /* packet protocol                */
		u_int32_t protoname;      /* protocol name                  */
		in_addr_t saddr;          /* source address                 */
		in_addr_t daddr;          /* destination address            */
	}ip;
	/* XXX UDP & TCP HEADER OPTIONS XXX                                 */
	u_int16_t  source ;       /* general source port                    */
	u_int16_t  dest;          /* general destination port               */
	/* XXX TCP HEADER OPTIONS XXX                                       */
	struct{
		u_int32_t seq;            /* initial sequence number        */
		u_int32_t ack_seq;        /* acklowdgement sequence         */
		u_int16_t fin;            /* end of data flag               */
		u_int16_t syn;            /* synchronize ISN flag           */
		u_int16_t rst;            /* reset connection flag          */
		u_int16_t psh;            /* push flag                      */
		u_int16_t ack;            /* acknowledgment # valid flag    */
		u_int16_t urg;            /* urgent pointer valid flag      */
		u_int16_t ece;            /* ecn-echo                       */
		u_int16_t cwr;            /* congestion windows reduced     */
		u_int16_t window;         /* TCP window size                */
		u_int16_t urg_ptr;        /* urgent pointer data            */
	}tcp;
	/* XXX ICMP HEADER OPTIONS XXX                                      */
	struct{
		u_int8_t  type;           /* control message type           */
		u_int8_t  code;           /* control message code           */
		u_int16_t id;             /* control message identification */
		u_int16_t sequence;       /* control message sequence       */
		in_addr_t gateway;        /* gateway address                */
	}icmp;
	/* XXX IGMP HEADER OPTIONS XXX                                      */
	struct{
		u_int8_t  type;           /* group type                     */
		u_int8_t  code;           /* group code                     */
		in_addr_t group;          /* group address                  */
	}igmp;
};


/* COMMON MACROS

   Common macros used by code.
   Any new macro routine should be added in this section. */
#ifdef  __32BIT_RND
#	warning "Sorry! The t50 is disabling __32BIT_RND!"
#	undef  __32BIT_RND
#	define __32BIT_RND(foo)                                                       \
		(foo == INADDR_ANY ?                                                  \
		(1 + (u_int32_t) (4294967295.0 * rand() / (RAND_MAX + 1.0))) :        \
		(u_int32_t) foo)
#else   /* __32BIT_RND */
#	define __32BIT_RND(foo)                                                       \
		(foo == INADDR_ANY ?                                                  \
		(1 + (u_int32_t) (4294967295.0 * rand() / (RAND_MAX + 1.0))) :        \
		(u_int32_t) foo)
#endif  /* __32BIT_RND */
#ifdef  __16BIT_RND
#	warning "Sorry! The t50 is disabling __16BIT_RND!"
#	undef  __16BIT_RND
#	define __16BIT_RND(foo)                                                       \
		(foo == IPPORT_ANY ?                                                  \
		(1 + (u_int16_t) (65535.0 * rand() / (RAND_MAX + 1.0))) :             \
		(u_int16_t) foo)
#else   /* __16BIT_RND */
#	define __16BIT_RND(foo)                                                       \
		(foo == IPPORT_ANY ?                                                  \
		(1 + (u_int16_t) (65535.0 * rand() / (RAND_MAX + 1.0))) :             \
		(u_int16_t) foo)
#endif  /* __16BIT_RND */
#ifdef  INADDR_RND
#	warning "Sorry! The t50 is disabling INADDR_RND!"
#	undef  INADDR_RND
#	define INADDR_RND(foo) __32BIT_RND(foo)
#else   /* INADDR_RND */
#	define INADDR_RND(foo) __32BIT_RND(foo)
#endif  /* INADDR_RND */
#ifdef  IPPORT_RND
#	warning "Sorry! The t50 is disabling IPPORT_RND!"
#	undef  IPPORT_RND
#	define IPPORT_RND(foo) __16BIT_RND(foo)
#else   /* IPPORT_RND */
#	define IPPORT_RND(foo) __16BIT_RND(foo)
#endif  /* IPPORT_RND */
#if     !defined (ar_sha) || !defined (ar_spa) || !defined (ar_tha) || !defined (ar_tpa)
/* XXX CHECK ME PLEASE XXX */
#	define ar_sha(foo)  (((foo)->ar_op) + 2)
#	define ar_spa(foo)  (ar_sha(foo)+(foo)->ar_hln)
#	define ar_tha(foo)  (ar_spa(foo)+(foo)->ar_pln)
#	define ar_tpa(foo)  (ar_tha(foo)+(foo)->ar_hln)
#endif  /* (ar_sha) || (ar_spa) || (ar_tha) || (ar_tpa) */
#ifdef  HWADDR_RND
#	warning "Sorry! The t50 is disabling HWADDR_RND!"
#	undef  HWADDR_RND
#	define HWADDR_RND(foo) do {                                                   \
		((u_int16_t *)foo)[0] = ((rand() & 0xffff) << 8) + (rand() & 0xffff); \
		((u_int16_t *)foo)[1] = ((rand() & 0xffff) << 8) + (rand() & 0xffff); \
		((u_int16_t *)foo)[2] = ((rand() & 0xffff) << 8) + (rand() & 0xffff); \
	} while (0)
#else   /* HWADDR_RND */
#	define HWADDR_RND(foo) do {                                                   \
		((u_int16_t *)foo)[0] = ((rand() & 0xffff) << 8) + (rand() & 0xffff); \
		((u_int16_t *)foo)[1] = ((rand() & 0xffff) << 8) + (rand() & 0xffff); \
		((u_int16_t *)foo)[2] = ((rand() & 0xffff) << 8) + (rand() & 0xffff); \
	} while (0)
#endif  /* HWADDR_RND */
#ifdef  ERR_DDEBUG
#	warning "Sorry! The t50 is disabling ERR_DDEBUG!"
#	undef  ERR_DDEBUG
#	define ERR_DDEBUG(foo) fprintf(stderr, "%s (%s): Error in function \'%s()\' line %d.\n", __FILE__, foo, __FUNCTION__, (__LINE__ - 2));
#else   /* ERR_DDEBUG */
#	define ERR_DDEBUG(foo) fprintf(stderr, "%s (%s): Error in function \'%s()\' line %d.\n", __FILE__, foo, __FUNCTION__, (__LINE__ - 2));
#endif  /* ERR_DDEBUG */
/* Using macro instead of function. This is kind of copyright. :P */
#ifdef  nb
#	warning "Sorry! The t50 is disabling nb!"
#	undef  nb
#	define nb(foo, bar) do {                                                      \
		fprintf(stdout, "%c", *foo++); fflush(stdout); usleep(bar);           \
	} while(*foo)
#else   /* nb */
#	define nb(foo, bar) do {                                                      \
		fprintf(stdout, "%c", *foo++); fflush(stdout); usleep(bar);           \
	} while(*foo)
#endif  /* nb */

/* COMMON ROUTINES

   Common routines used by code.
   Any new routine should be added in this section. */
/* Function Name: Command line interface options validation. */
extern u_int32_t check(const struct config_options, const int8_t *);
/* Function Name: Checksum calculation. */
extern u_int16_t cksum(u_int16_t *, int32_t);
/* Function Name: Command line interface options configuration. */
extern struct config_options config(int32_t, int8_t **);
/* Function Name: ICMP packet header configuration. */
 __inline__ extern const void * icmp(const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: IGMP packet header configuration. */
 __inline__ extern const void * igmp(const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: IP address and name resolve. */
extern in_addr_t resolv(int8_t *);
/* Function Name: Socket configuration. */
extern socket_t sock(void);
/* Function Name: TCP packet header configuration. */
__inline__ extern const void * tcp(const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: UDP packet header configuration. */
__inline__ extern const void * udp(const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: Help and usage message. */
extern void usage(int8_t *, int8_t *, int8_t *);

__END_DECLS

#ifdef __cplusplus
}
#endif

#endif  /* __COMMON_H */
