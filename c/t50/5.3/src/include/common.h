/* 
 * $Id: common.h,v 5.58 2011-03-11 14:42:15-03 nbrito Exp $
 */

/***************************************************************************
  ___________._______________
  \__    ___/|   ____/\   _  \   T50: an Experimental Packet Injector Tool
    |    |   |____  \ /  /_\  \                 Release 5.3
    |    |   /       \\  \_/   \
    |____|  /______  / \_____  /   Copyright (c) 2001-2011 Nelson Brito
                   \/        \/             All Rights Reserved

 ***************************************************************************
 * Author: Nelson Brito <nbrito@sekure.org>                                *
 *                                                                         *
 * Copyright (c) 2001-2011 Nelson Brito. All rights reserved worldwide.    *
 *                                                                         *
 * The following text was taken borrowed from Nmap License.                *
 ************************IMPORTANT T50 LICENSE TERMS************************
 *                                                                         *
 * T50 is program is free software;  you may redistribute and/or modify it *
 * under the terms of the 'GNU General Public License' as published by the *
 * Free  Software  Foundation;  Version  2  with  the  clarifications  and *
 * exceptions described below.  This guarantees your right to use, modify, *
 * and redistribute this software under certain conditions. If you wish to *
 * embed T50 technology into  proprietary software,  please,  contact  the *
 * author for an alternative license (contact nbrito@sekure.org).          *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it  does  not provide a  detailed  definition of  that  term.  To avoid *
 * misunderstandings, the author considers an application  to constitute a *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * 1 Integrates source code from T50.                                      *
 * 2 Reads or includes T50 copyrighted data files, such: protocol modules, *
 *   configuration files or libraries.                                     *
 * 3 Integrates, includes or aggregates  T50 into a proprietary executable *
 *   installer, such as those produced by InstallShield.                   *
 * 4 Links to a library or executes a program that does any of the above.  *
 *                                                                         *
 * The term "T50" should be  taken to also include any portions or derived *
 * works of T50.  This list is not exclusive,  but is meant to clarify the *
 * author's interpretation  of  "derived works" with some common examples. *
 * The author's interpretation applies only to T50 -- he doesn't speak for *
 * other people's GPL works.                                               *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * T50 in non-GPL works,  the author would be happy to help.  As mentioned *
 * above, the author also offers alternative license to integrate T50 into *
 * proprietary  applications  and  appliances.  These  licenses  generally *
 * include  a  perpetual license as well as providing for priority support *
 * and updates as well as helping to fund the continued development of T50 *
 * technology.  Please email nbrito@sekure.org for further information.    *
 *                                                                         *
 * If  you  received these files  with  a  written  license  agreement  or *
 * contract  stating   terms  other   than  the  terms  above,  then  that *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to  this software because the author  believes users *
 * have a right to know exactly what a program  is going to do before they *
 * run it.  This also allows you to audit the software for security holes, *
 * but none have been found so far.                                        *
 *                                                                         *
 * Source code also allows you to port T50 to new platforms, fix bugs, and *
 * add new features and new protocol modules. You are highly encouraged to *
 * send your changes to nbrito@sekure.org for possible  incorporation into *
 * the main distribution. By sending these changes to Nelson Brito,  it is *
 * assumed  that you are  offering the  T50 Project,  and its author,  the *
 * unlimited,  non-exclusive right to reuse,  modify,  and  relicense  the *
 * code.  T50 will always be available Open Source,  but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects  (such  as  KDE and NASM).  The author *
 * also  occasionally  relicense  the  code  to third parties as discussed *
 * above.  If  you wish to  specify  special license  conditions  of  your *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This  program  is distributed in the hope that it will  be useful,  but *
 * WITHOUT  ANY  WARRANTY;    without   even   the   implied  warranty  of *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    *
 * Please, refer to GNU General Public License v2.0 for further details at *
 * http://www.gnu.org/licenses/gpl-2.0.html,  or  in the  LICENSE document *
 * included with T50.                                                      *
 ***************************************************************************/
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
#ifdef  __HAVE_CIDR__
#include <math.h>
#endif  /* __HAVE_CIDR__ */
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
#include <sys/socket.h>
#include <sys/resource.h>
/*
 * This code prefers to use Linux headers rather than BSD favored.
 */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/dccp.h>
#include <linux/if_ether.h>
/*
 * Purpose-built config library to be used by T50 modules.
 */
#include <config.h>
/*
 * Purpose-built protocol libraries to be used by T50 modules.
 */
#include <protocol/egp.h>
#include <protocol/gre.h>
#include <protocol/rip.h>
#include <protocol/igmp.h>
#include <protocol/ospf.h>
#include <protocol/rsvp.h>
#include <protocol/eigrp.h>
#include <protocol/tcp_options.h>


#ifdef __cplusplus
extern "C" {
#endif


__BEGIN_DECLS


/* GLOBAL VERSION DEFINITIONS

   Global version definitions used by code.
   Any new global version definition should be added in this section. */
#ifndef MAJOR_VERSION
#	define MAJOR_VERSION          __STRING(5)
#endif  /* MAJOR_VERSION */
#ifndef MINOR_VERSION
#	define MINOR_VERSION          __STRING(3)
#endif  /* MINOR_VERSION */
#ifndef T50_REVISION
#	define T50_REVISION           __STRING(16)
#endif  /* T50_REVISION */
#ifndef BUILD_VERSION
#	define BUILD_VERSION          __STRING(110312)
#endif  /* BUILD_VERSION */
#ifndef BUILD_PLATFORM
#	if     __WORDSIZE == 32
#		define BUILD_PLATFORM __STRING(32-bit)
#	elif   __WORDSIZE == 64
#		define BUILD_PLATFORM __STRING(64-bit)
#	else   /* __WORDSIZE */
#		define BUILD_PLATFORM __STRING(generic)
#	endif  /* __WORDSIZE */

#endif  /* BUILD_PLATFORM */


/* GLOBAL LICENSE DEFINITIONS

   Global license definitions used by code.
   Any new global license definition should be added in this section. */
#ifndef REGISTERED_USER
#	define REGISTERED_USER        __STRING(kiddo)
#endif  /* REGISTERED_USER */
#ifndef REGISTERED_FQDN
#	define REGISTERED_FQDN        __STRING(lammer.com)
#endif  /* REGISTERED_FQDN */
#ifdef  __HAVE_RESTRICTION__
#	define __HAVE_EXPIRATION__    1
#	define __HAVE_LIMITATION__    1
#endif  /* __HAVE_RESTRICTION__ */
#ifdef  __HAVE_EXPIRATION__
#	if     !(EXPIRATION_LAST_HOUR)
#		define EXPIRATION_LAST_HOUR   23
#	elif   (EXPIRATION_LAST_HOUR < 1)
#		error "Sorry! The t50 EXPIRATION_LAST_HOUR cannot be smaller than 1!"
#	endif  /* (EXPIRATION_LAST_HOUR) */
#	if     !(EXPIRATION_LAST_MINUTE)
#		define EXPIRATION_LAST_MINUTE 59
#	elif   (EXPIRATION_LAST_MINUTE < 1)
#		error "Sorry! The t50 EXPIRATION_LAST_MINUTE cannot be smaller than 1!"
#	endif  /* (EXPIRATION_LAST_MINUTE) */
#	if     !(EXPIRATION_LAST_SECOND)
#		define EXPIRATION_LAST_SECOND 60
#	elif   (EXPIRATION_LAST_SECOND < 1)
#		error "Sorry! The t50 EXPIRATION_LAST_SECOND cannot be smaller than 1!"
#	endif  /* (EXPIRATION_LAST_SECOND) */
#	if     !(EXPIRATION_FIRST_DAY)
#		define EXPIRATION_FIRST_DAY   1
#	elif   (EXPIRATION_FIRST_DAY < 1)
#		error "Sorry! The t50 EXPIRATION_FIRST_DAY cannot be smaller than 1!"
#	endif  /* (EXPIRATION_FIRST_DAY) */
#	if     !(EXPIRATION_LAST_DAY)
#		define EXPIRATION_LAST_DAY   30
#	elif   (EXPIRATION_LAST_DAY > 30)
#		error "Sorry! The t50 EXPIRATION_LAST_DAY cannot be greater than 30!"
#	endif  /* (EXPIRATION_LAST_DAY) */
#	if     !(EXPIRATION_MONTH)
#		define EXPIRATION_MONTH      1
#	elif   ((EXPIRATION_MONTH > 12) || (EXPIRATION_MONTH < 1))
#		error "Sorry! The t50 EXPIRATION_MONTH cannot be greater than 12 or smaller than 1!"
#	endif  /* (EXPIRATION_MONTH) */
#	if     (EXPIRATION_FIRST_DAY > EXPIRATION_LAST_DAY)
#		error "Sorry! The t50 EXPIRATION_FIRST_DAY cannot be greater than EXPIRATION_LAST_DAY!"
#	endif  /* (EXPIRATION_FIRST_DAY > EXPIRATION_LAST_DAY) */
#	if     !(EXPIRATION_YEAR)
#		define EXPIRATION_YEAR       2011
#	endif  /* (EXPIRATION_YEAR) */
#endif  /* __HAVE_EXPIRATION__ */


/* GLOBAL COMMON DEFINITIONS

   Global common definitions used by code.
   Any new global common definition should be added in this section. */
#ifdef  RAND_MAX
/* Disabling warning.
#	warning "Sorry! The t50 is disabling RAND_MAX!" */
#	undef  RAND_MAX
#	define RAND_MAX               2147483647
#else   /* RAND_MAX */
#	define RAND_MAX               2147483647
#endif  /* RAND_MAX */
#ifdef  __HAVE_CIDR__
#	ifdef  CIDR_MINIMUM
#		warning "Sorry! The t50 is disabling CIDR_MINIMUM!"
#		undef  CIDR_MINIMUM
#		define CIDR_MINIMUM   8
#	else   /* CIDR_MINIMUM */
#		define CIDR_MINIMUM   8
#	endif  /* CIDR_MINIMUM */
#	ifdef  CIDR_MAXIMUM
#		warning "Sorry! The t50 is disabling CIDR_MAXIMUM!"
#		undef  CIDR_MAXIMUM
#		define CIDR_MAXIMUM   30
#	else   /* CIDR_MAXIMUM */
#		define CIDR_MAXIMUM   30
#	endif  /* CIDR_MAXIMUM */
#	ifdef  MAXIMUM_IP_ADDRESSES
#		warning "Sorry! The t50 is disabling MAXIMUM_IP_ADDRESSES!"
#		undef  MAXIMUM_IP_ADDRESSES
#		define MAXIMUM_IP_ADDRESSES  16777215
#	else   /* MAXIMUM_IP_ADDRESSES */
#		define MAXIMUM_IP_ADDRESSES  16777215
#	endif  /* MAXIMUM_IP_ADDRESSES */
#endif  /* __HAVE_CIDR__ */
#ifdef  int8_t
#	warning "Sorry! The t50 is disabling int8_t!"
#	undef  int8_t
#	define int8_t                 char
#else     /* int8_t */
#	define int8_t                 char
#endif  /* int8_t */
#ifdef  u_int8_t
#	warning "Sorry! The t50 is disabling u_int8_t!"
#	undef  u_int8_t
#	define u_int8_t               unsigned char
#else   /* u_int8_t */
#	define u_int8_t               unsigned char
#endif  /* u_int8_t */
#ifdef  int16_t
#	warning "Sorry! The t50 is disabling int16_t!"
#	undef  int16_t
#	define int16_t                short
#else   /* int16_t */
#	define int16_t                short
#endif  /* int16_t */
#ifdef  u_int16_t
#	warning "Sorry! The t50 is disabling u_int16_t!"
#	undef u_int16_t
#	define u_int16_t              unsigned short
#else   /* u_int16_t */
#	define u_int16_t              unsigned short
#endif  /* u_int16_t */
#ifdef  int32_t
#	warning "Sorry! The t50 is disabling int32_t!"
#	undef  int32_t
#	define int32_t                int
#else   /* int32_t */
#	define int32_t                int
#endif  /* int32_t */
#ifdef  u_int32_t
#	warning "Sorry! The t50 is disabling u_int32_t!"
#	undef  u_int32_t
#	define u_int32_t              unsigned int
#else   /* u_int32_t */
#	define u_int32_t              unsigned int
#endif  /* u_int32_t */
#ifdef  int64_t
#	warning "Sorry! The t50 is disabling int64_t!"
#	undef  int64_t
#	define int64_t                long int
#else   /* int64_t */
#	define int64_t                long int
#endif  /* int64_t */
#ifdef  u_int64_t
#	warning "Sorry! The t50 is disabling u_int64_t!"
#	undef  u_int64_t
#	define u_int64_t              unsigned long int
#else   /* u_int64_t */
#	define u_int64_t              unsigned long int
#endif  /* u_int64_t */
#ifdef  in_addr_t
#	warning "Sorry! The t50 is disabling in_addr_t!"
#	undef  in_addr_t
#	define in_addr_t              u_int32_t
#else   /* in_addr_t */
#	define in_addr_t              u_int32_t
#endif  /* in_addr_t */
#ifdef  socket_t
#	warning "Sorry! The t50 is disabling socket_t!"
#	undef  socket_t
#	define socket_t               int32_t
#else   /* socket_t */
#	define socket_t               int32_t
#endif  /* socket_t */
#ifdef  INADDR_ANY
/* Disabling warning.
#	warning "Sorry! The t50 is disabling INADDR_ANY!" */
#	undef  INADDR_ANY
#	define INADDR_ANY             ((in_addr_t) 0x00000000)
#else   /* INADDR_ANY */
#	define INADDR_ANY             ((in_addr_t) 0x00000000)
#endif  /* INADDR_ANY */
#ifdef  IPPORT_ANY
#	warning "Sorry! The t50 is disabling IPPORT_ANY!"
#	undef  IPPORT_ANY
#	define IPPORT_ANY             ((u_int16_t) 0x0000)
#else   /* IPPORT_ANY */
#	define IPPORT_ANY             ((u_int16_t) 0x0000)
#endif  /* IPPORT_ANY */


/* GLOBAL VARIABLES

   Global variables used by code.
   Any new global variable should be added in this section. */
#if     (T50_C__) || (CONFIG_C__) || ((CIDR_C__) && (__HAVE_CIDR__))
static int8_t * program     =   "t50";
#	ifdef  T50_C__
static int8_t * months[]    = { 
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
				"Dec",
				NULL 
};
#	endif  /* T50_C__ */
#	ifdef  CONFIG_C__
static int8_t * author      =   "Nelson Brito";
static int8_t * email       =   "nbrito@sekure.org";
static int8_t * copyright   =   "/****************************************************************************\n"
				"   ___________._______________\n"
				"   \\__    ___/|   ____/\\   _  \\   T50: an Experimental Packet Injector Tool\n"
				"     |    |   |____  \\ /  /_\\  \\                 Release 5.3\n"
				"     |    |   /       \\\\  \\_/   \\\n"
				"     |____|  /______  / \\_____  /   Copyright (c) 2001-2011 Nelson Brito\n"
				"                    \\/        \\/             All Rights Reserved\n\n"
				" ****************************************************************************\n"
				" * Author: Nelson Brito <nbrito@sekure.org>                                 *\n"
				" *                                                                          *\n"
				" * Copyright (c) 2001-2011 Nelson Brito. All rights reserved worldwide.     *\n"
				" ****************************************************************************/\n";
#	endif  /* CONFIG_C__ */
#endif  /* (T50_C__) || (CONFIG_C__) */
#if     ((CHECK_C__) && (__HAVE_T50__)) || (CONFIG_C__)
static int8_t * modules[]   = {
				"ICMP",
				"IGMPv1",
				"IGMPv3",
				"TCP",
				"EGP",
				"UDP",
				"RIPv1",
				"RIPv2",
				"DCCP",
				"RSVP",
				"IPSEC",
				"EIGRP",
				"OSPF",
#	ifdef  __HAVE_T50__
				"T50",
#	endif  /* __HAVE_T50__ */
				NULL
};
#	if     (CONFIG_C__) && (__HAVE_USAGE__)
static int8_t * mod_names[] = {
				"Internet Control Message Protocol",
				"Internet Group Message Protocol v1",
				"Internet Group Message Protocol v3",
				"Transmission Control Protocol",
				"Exterior Gateway Protocol",
				"User Datagram Protocol",
				"Routing Information Protocol v1",
				"Routing Information Protocol v2",
				"Datagram Congestion Control Protocol",
				"Resource ReSerVation Protocol",
				"Internet Protocol Security (AH/ESP)",
				"Enhanced Interior Gateway Routing Protocol",
				"Open Shortest Path First",
#	ifdef  __HAVE_T50__
				"Experimental Mixed Packet Injector",
#	endif  /* __HAVE_T50__ */
				NULL
};
#	endif  /* (CONFIG_C__)  && (__HAVE_USAGE__) */
#endif  /* ((CHECK_C__) && (__HAVE_T50__)) || (CONFIG_C__) */
enum t50_module{
	MODULE_ICMP                =  0,
#define MODULE_ICMP                   MODULE_ICMP
	MODULE_IGMPv1,
#define MODULE_IGMPv1                 MODULE_IGMPv1
	MODULE_IGMPv3,
#define MODULE_IGMPv3                 MODULE_IGMPv3
	MODULE_TCP,
#define MODULE_TCP                    MODULE_TCP
	MODULE_EGP,
#define MODULE_EGP                    MODULE_EGP
	MODULE_UDP,
#define MODULE_UDP                    MODULE_UDP
	MODULE_RIPv1,
#define MODULE_RIPv1                  MODULE_RIPv1
	MODULE_RIPv2,
#define MODULE_RIPv2                  MODULE_RIPv2
	MODULE_DCCP,
#define MODULE_DCCP                   MODULE_DCCP
	MODULE_RSVP,
#define MODULE_RSVP                   MODULE_RSVP
	MODULE_IPSEC,
#define MODULE_IPSEC                  MODULE_IPSEC
	MODULE_EIGRP,
#define MODULE_EIGRP                  MODULE_EIGRP
	MODULE_OSPF,
#define MODULE_OSPF                   MODULE_OSPF
#ifdef  __HAVE_T50__
	MODULE_T50,
#	define MODULE_T50             MODULE_T50
#	ifdef  T50_THRESHOLD_MIN
#		warning "Sorry! The t50 is disabling T50_THRESHOLD_MIN!"
#		undef  T50_THRESHOLD_MIN
#		define T50_THRESHOLD_MIN     MODULE_T50
#	else   /* T50_THRESHOLD_MIN */
#		define T50_THRESHOLD_MIN     MODULE_T50
#	endif  /* T50_THRESHOLD_MIN */
#endif  /* __HAVE_T50__ */
};


/* GLOBAL COMMON PROTOCOL DEFINITIONS

   Global common protocol definitions used by code.
   Any new global common protocol definition should be added in this section. */
#ifdef  AUTH_TYPE_HMACNUL
#	warning "Sorry! The t50 is disabling AUTH_TYPE_HMACNUL!"
#	undef  AUTH_TYPE_HMACNUL
#	define AUTH_TYPE_HMACNUL      0x0000
#else   /* AUTH_TYPE_HMACNUL */
#	define AUTH_TYPE_HMACNUL      0x0000
#endif  /* AUTH_TYPE_HMACNUL */
#ifdef  AUTH_TYPE_HMACMD5
#	warning "Sorry! The t50 is disabling AUTH_TYPE_HMACMD5!"
#	undef  AUTH_TYPE_HMACMD5
#	define AUTH_TYPE_HMACMD5      0x0002
#else   /* AUTH_TYPE_HMACMD5 */
#	define AUTH_TYPE_HMACMD5      0x0002
#endif  /* AUTH_TYPE_HMACMD5 */
#ifdef  AUTH_TLEN_HMACMD5
#	warning "Sorry! The t50 is disabling AUTH_TLEN_HMACMD5!"
#	undef  AUTH_TLEN_HMACMD5
#	define AUTH_TLEN_HMACMD5      16
#else   /* AUTH_TLEN_HMACMD5 */
#	define AUTH_TLEN_HMACMD5      16
#endif  /* AUTH_TLEN_HMACMD5 */
#ifdef  auth_hmac_md5_len
#	warning "Sorry! The t50 is disabling auth_hmac_md5_len!"
#	undef  auth_hmac_md5_len
#	define auth_hmac_md5_len(foo) \
			(foo  ? AUTH_TLEN_HMACMD5 : 0)
#else   /* auth_hmac_md5_len */
#	define auth_hmac_md5_len(foo) \
			(foo ? AUTH_TLEN_HMACMD5 : 0)
#endif  /* auth_hmac_md5_len */
#ifdef  IPVERSION
/* Disabling warning.
#	warning "Sorry! The t50 is disabling IPVERSION!" */
#	undef  IPVERSION
#	define IPVERSION              4
#else   /* IPVERSION */
#	define IPVERSION              4
#endif  /* IPVERSION */
#ifdef  IP_MF
#	warning "Sorry! The t50 is disabling IP_MF!"
#	undef  IP_MF
#	define IP_MF                  0x2000
#else   /* IP_MF */
#	define IP_MF                  0x2000
#endif  /* IP_MF */
#ifdef  IP_DF
#	warning "Sorry! The t50 is disabling IP_MF!"
#	undef  IP_DF
#	define IP_DF                  0x4000
#else   /* IP_DF */
#	define IP_DF                  0x4000
#endif  /* IP_DF */
/* T50 DEFINITIONS. */
#ifdef  __t50
#	warning "Sorry! The t50 is disabling __t50()!"
#	undef  __t50
#	define __t50(foo, bar) main(foo, bar)
#else   /* __t50 */
#	define __t50(foo, bar) main(foo, bar)
#endif  /* __t50 */
#ifdef  IPPROTO_T50
#	warning "Sorry! The t50 is disabling IPPROTO_T50!"
#	undef  IPPROTO_T50
#	define IPPROTO_T50            69
#else   /* IPPROTO_T50 */
#	define IPPROTO_T50            69
#endif  /* IPPROTO_T50 */
#ifdef  FIELD_MUST_BE_NULL
#	warning "Sorry! The t50 is disabling FIELD_MUST_BE_NULL!"
#	undef  FIELD_MUST_BE_NULL
#	define FIELD_MUST_BE_NULL     NULL
#else   /* FIELD_MUST_BE_NULL */
#	define FIELD_MUST_BE_NULL     NULL
#endif  /* FIELD_MUST_BE_NULL */
#ifdef  FIELD_MUST_BE_ZERO
#	warning "Sorry! The t50 is disabling FIELD_MUST_BE_ZERO!"
#	undef  FIELD_MUST_BE_ZERO
#	define FIELD_MUST_BE_ZERO     0
#else   /* FIELD_MUST_BE_ZERO */
#	define FIELD_MUST_BE_ZERO     0
#endif  /* FIELD_MUST_BE_ZERO */


/* COMMON PROTOCOL STRUCTURES

   Common protocol structures used by code.
   Any new common protocol structure should be added in this section. */
/*
 * User Datagram Protocol (RFC 768)
 *
 * Checksum is the 16-bit one's complement of the one's complement sum of a
 * pseudo header of information from the IP header, the UDP header, and the
 * data,  padded  with zero octets  at the end (if  necessary)  to  make  a
 * multiple of two octets.
 *
 * The pseudo  header  conceptually prefixed to the UDP header contains the
 * source  address,  the destination  address,  the protocol,  and the  UDP
 * length.   This information gives protection against misrouted datagrams.
 * This checksum procedure is the same as is used in TCP.
 *
 *                   0      7 8     15 16    23 24    31 
 *                  +--------+--------+--------+--------+
 *                  |          source address           |
 *                  +--------+--------+--------+--------+
 *                  |        destination address        |
 *                  +--------+--------+--------+--------+
 *                  |  zero  |protocol|   UDP length    |
 *                  +--------+--------+--------+--------+
 *
 * If the computed  checksum  is zero,  it is transmitted  as all ones (the
 * equivalent  in one's complement  arithmetic).   An all zero  transmitted
 * checksum  value means that the transmitter  generated  no checksum  (for
 * debugging or for higher level protocols that don't care). 
 */
struct psdhdr{
 	in_addr_t saddr;                  /* source address              */
	in_addr_t daddr;                  /* destination address         */
	u_int8_t  zero;                   /* must be zero                */
	u_int8_t  protocol;               /* protocol                    */
	u_int16_t len;                    /* header length               */
};


/* COMMON MACROS

   Common macros used by code.
   Any new macro routine should be added in this section. */
#ifdef  __32BIT_RND
#	warning "Sorry! The t50 is disabling __32BIT_RND!"
#	undef  __32BIT_RND
#	define __32BIT_RND(foo) \
		(foo == 0x00000000 ? \
			(1 + (u_int32_t) (4294967295.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int32_t) foo)
#else   /* __32BIT_RND */
#	define __32BIT_RND(foo) \
		(foo == 0x00000000 ? \
			(1 + (u_int32_t) (4294967295.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int32_t) foo)
#endif  /* __32BIT_RND */
#ifdef  __24BIT_RND
#	warning "Sorry! The t50 is disabling __24BIT_RND!"
#	undef  __24BIT_RND
#	define __24BIT_RND(foo) \
		(foo == 0x000000 ? \
			(1 + (u_int32_t) (16777215.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int32_t) foo)
#else   /* __24BIT_RND */
#	define __24BIT_RND(foo) \
		(foo == 0x000000 ? \
			(1 + (u_int32_t) (16777215.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int32_t) foo)
#endif  /* __24BIT_RND */
#ifdef  __16BIT_RND
#	warning "Sorry! The t50 is disabling __16BIT_RND!"
#	undef  __16BIT_RND
#	define __16BIT_RND(foo) \
		(foo == 0x0000 ? \
			(1 + (u_int16_t) (65535.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int16_t) foo)
#else   /* __16BIT_RND */
#	define __16BIT_RND(foo) \
		(foo == 0x0000 ? \
			(1 + (u_int16_t) (65535.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int16_t) foo)
#endif  /* __16BIT_RND */
#ifdef  __8BIT_RND
#	warning "Sorry! The t50 is disabling __8BIT_RND!"
#	undef  __8BIT_RND
#	define __8BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (255.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#else   /* __8BIT_RND */
#	define __8BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (255.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#endif  /* __8BIT_RND */
#ifdef  __7BIT_RND
#	warning "Sorry! The t50 is disabling __7BIT_RND!"
#	undef  __7BIT_RND
#	define __7BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (127.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#else   /* __7BIT_RND */
#	define __7BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (127.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#endif  /* __7BIT_RND */
#ifdef  __6BIT_RND
#	warning "Sorry! The t50 is disabling __6BIT_RND!"
#	undef  __6BIT_RND
#	define __6BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (63.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#else   /* __6BIT_RND */
#	define __6BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (63.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#endif  /* __6BIT_RND */
#ifdef  __5BIT_RND
#	warning "Sorry! The t50 is disabling __5BIT_RND!"
#	undef  __5BIT_RND
#	define __5BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (31.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#else   /* __5BIT_RND */
#	define __5BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (31.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#endif  /* __5BIT_RND */
#ifdef  __4BIT_RND
#	warning "Sorry! The t50 is disabling __4BIT_RND!"
#	undef  __4BIT_RND
#	define __4BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (15.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#else   /* __4BIT_RND */
#	define __4BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (15.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#endif  /* __4BIT_RND */
#ifdef  __3BIT_RND
#	warning "Sorry! The t50 is disabling __3BIT_RND!"
#	undef  __3BIT_RND
#	define __3BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (7.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#else   /* __3BIT_RND */
#	define __3BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (7.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#endif  /* __3BIT_RND */
#ifdef  __2BIT_RND
#	warning "Sorry! The t50 is disabling __2BIT_RND!"
#	undef  __2BIT_RND
#	define __2BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (2.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#else   /* __2BIT_RND */
#	define __2BIT_RND(foo) \
		(foo == 0 ? \
			(1 + (u_int8_t) (2.0 * rand() / (RAND_MAX + 1.0))) : \
		(u_int8_t) foo)
#endif  /* __2BIT_RND */
#ifdef  INADDR_RND
#	warning "Sorry! The t50 is disabling INADDR_RND!"
#	undef  INADDR_RND
#	define INADDR_RND(foo) \
		__32BIT_RND(foo)
#else   /* INADDR_RND */
#	define INADDR_RND(foo) \
		__32BIT_RND(foo)
#endif  /* INADDR_RND */
#ifdef  NETMASK_RND
#	warning "Sorry! The t50 is disabling NETMASK_RND!"
#	undef  NETMASK_RND
#	define NETMASK_RND(foo) \
		htonl(foo == INADDR_ANY ? \
			~(0xffffffff >> (8 + (u_int32_t) (23.0 * rand() / (RAND_MAX + 1.0)))) : \
		(u_int32_t) foo)
#else   /* NETMASK_RND */
#	define NETMASK_RND(foo) \
		htonl(foo == INADDR_ANY ? \
			~(0xffffffff >> (8 + (u_int32_t) (23.0 * rand() / (RAND_MAX + 1.0)))) : \
		(u_int32_t) foo)
#endif  /* NETMASK_RND */
#ifdef  IPPORT_RND
#	warning "Sorry! The t50 is disabling IPPORT_RND!"
#	undef  IPPORT_RND
#	define IPPORT_RND(foo) \
		__16BIT_RND(foo)
#else   /* IPPORT_RND */
#	define IPPORT_RND(foo) \
		__16BIT_RND(foo)
#endif  /* IPPORT_RND */
#ifdef  ERR_DDEBUG
#	warning "Sorry! The t50 is disabling ERR_DDEBUG!"
#	undef  ERR_DDEBUG
#	define ERR_DDEBUG(foo) \
		fprintf(stderr, \
			"%s (%s): Error in function \'%s()\' line %d.\n", \
			__FILE__, \
			foo, \
			__FUNCTION__, \
			(__LINE__ - 2));
#else   /* ERR_DDEBUG */
#	define ERR_DDEBUG(foo) \
		fprintf(stderr, \
			"%s (%s): Error in function \'%s()\' line %d.\n", \
			__FILE__, \
			foo, \
			__FUNCTION__, \
			(__LINE__ - 2));
#endif  /* ERR_DDEBUG */
/* Using macro instead of function. This is kind of copyright. :P */
#ifdef  nb
#	warning "Sorry! The t50 is disabling nb!"
#	undef  nb
#	define nb(foo, bar) \
		do{ \
			fprintf(stdout, \
				"%c", \
				*foo++); \
			fflush(stdout); \
			usleep(bar); \
		}while(*foo)
#else   /* nb */
#	define nb(foo, bar) \
		do{ \
			fprintf(stdout, \
				"%c", \
				*foo++); \
			fflush(stdout); \
			usleep(bar); \
		}while(*foo)
#endif  /* nb */

/* COMMON ROUTINES

   Common routines used by code.
   Any new routine should be added in this section. */
#ifdef  __HAVE_CIDR__
/* Function Name: CIDR configuration tiny algorithm. */
extern struct cidr config_cidr(u_int32_t, in_addr_t);
#endif  /* __HAVE_CIDR__ */
/* Function Name: Command line interface options validation. */

extern u_int32_t check(const struct config_options, const int8_t *);
/* Function Name: Checksum calculation. */
extern u_int16_t cksum(u_int16_t *, int32_t);
/* Function Name: Command line interface options configuration. */
extern struct config_options config (int32_t, int8_t **);
/* Function Name: IP address and name resolve. */
extern in_addr_t resolv(int8_t *);
/* Function Name: Socket configuration. */
extern socket_t sock(void);
/* Function Name: Help and usage message. */
extern void usage(int8_t *, int8_t *, int8_t *);


/* COMMON MODULE ROUTINES

   Common module routines used by code.
   Any new module routine should be added in this section. */
/* Function Name: ICMP packet header configuration. */
__inline__ extern const void * icmp   (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: IGMPv1 packet header configuration. */
__inline__ extern const void * igmpv1 (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: IGMPv3 packet header configuration. */
__inline__ extern const void * igmpv3 (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: TCP packet header configuration. */
__inline__ extern const void * tcp    (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: EGP packet header configuration. */
__inline__ extern const void * egp    (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: UDP packet header configuration. */
__inline__ extern const void * udp    (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: RIPv1 packet header configuration. */
__inline__ extern const void * ripv1  (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: RIPv2 packet header configuration. */
__inline__ extern const void * ripv2  (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: DCCP packet header configuration. */
__inline__ extern const void * dccp   (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: RSVP packet header configuration. */
__inline__ extern const void * rsvp   (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: IPSec packet header configuration. */
__inline__ extern const void * ipsec  (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: EIGRP packet header configuration. */
__inline__ extern const void * eigrp  (const socket_t, const struct config_options) __attribute__((always_inline));
/* Function Name: OSPF packet header configuration. */
__inline__ extern const void * ospf   (const socket_t, const struct config_options) __attribute__((always_inline));


__END_DECLS


#ifdef __cplusplus
}
#endif


#endif  /* __COMMON_H */
