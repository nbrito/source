/* 
 * $Id: rsvp.h,v 5.3 2011-03-09 19:32:20-03 nbrito Exp $
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
#ifndef __RSVP_H
#define __RSVP_H 1


/* GLOBAL HEADERS/INCLUDES

   Global headers/includes used by code.
   Any new global headers/includes should be added in this section. */
#include <common.h>


#ifdef __cplusplus
extern "C" {
#endif


__BEGIN_DECLS


/* GLOBAL RSVP PROTOCOL DEFINITIONS

   Global RSVP protocol definitions used by code.
   Any new global RSVP protocol definition should be added in this section. */
#ifdef  RSVPVERSION
#	warning "Sorry! The t50 is disabling RSVPVERSION!"
#	undef  RSVPVERSION
#	define RSVPVERSION 1
#else   /* RSVPVERSION */
#	define RSVPVERSION 1
#endif  /* RSVPVERSION */
/* RSVP Message Type */
enum rsvp_type{
	RSVP_MESSAGE_TYPE_PATH      = 1,
#define RSVP_MESSAGE_TYPE_PATH        RSVP_MESSAGE_TYPE_PATH
	RSVP_MESSAGE_TYPE_RESV,
#define RSVP_MESSAGE_TYPE_RESV        RSVP_MESSAGE_TYPE_RESV
	RSVP_MESSAGE_TYPE_PATHERR,
#define RSVP_MESSAGE_TYPE_PATHERR     RSVP_MESSAGE_TYPE_PATHERR
	RSVP_MESSAGE_TYPE_RESVERR,
#define RSVP_MESSAGE_TYPE_RESVERR     RSVP_MESSAGE_TYPE_RESVERR
	RSVP_MESSAGE_TYPE_PATHTEAR,
#define RSVP_MESSAGE_TYPE_PATHTEAR    RSVP_MESSAGE_TYPE_PATHTEAR
	RSVP_MESSAGE_TYPE_RESVTEAR,
#define RSVP_MESSAGE_TYPE_RESVTEAR    RSVP_MESSAGE_TYPE_RESVTEAR
	RSVP_MESSAGE_TYPE_RESVCONF,
#define RSVP_MESSAGE_TYPE_RESVCONF    RSVP_MESSAGE_TYPE_RESVCONF
	RSVP_MESSAGE_TYPE_BUNDLE    = 12,
#define RSVP_MESSAGE_TYPE_BUNDLE      RSVP_MESSAGE_TYPE_BUNDLE
	RSVP_MESSAGE_TYPE_ACK,
#define RSVP_MESSAGE_TYPE_ACK         RSVP_MESSAGE_TYPE_ACK
	RSVP_MESSAGE_TYPE_SREFRESH  = 15,
#define RSVP_MESSAGE_TYPE_SREFRESH    RSVP_MESSAGE_TYPE_SREFRESH
	RSVP_MESSAGE_TYPE_HELLO     = 20,
#define RSVP_MESSAGE_TYPE_HELLO       RSVP_MESSAGE_TYPE_HELLO
	RSVP_MESSAGE_TYPE_NOTIFY,
#define RSVP_MESSAGE_TYPE_NOTIFY      RSVP_MESSAGE_TYPE_NOTIFY
};
/*
 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
 *
 * 3.1.2 Object Formats
 *
 *       Every  object  consists of  one or more 32-bit words with a one-
 *       word header, with the following format:
 *
 *          0             1              2             3
 *   +-------------+-------------+-------------+-------------+
 *   |       Length (bytes)      |  Class-Num  |   C-Type    |
 *   +-------------+-------------+-------------+-------------+
 *   |                                                       |
 *   //                  (Object contents)                   //
 *   |                                                       |
 *   +-------------+-------------+-------------+-------------+
 */
#ifdef  RSVP_OBJECT_HEADER_LENGTH
#	warning "Sorry! The t50 is disabling RSVP_OBJECT_HEADER_LENGTH!"
#	undef  RSVP_OBJECT_HEADER_LENGTH
#	define RSVP_OBJECT_HEADER_LENGTH \
			(sizeof(u_int16_t) + \
			(sizeof(u_int8_t) * 2))
#else   /* RSVP_OBJECT_HEADER_LENGTH */
#	define RSVP_OBJECT_HEADER_LENGTH \
			(sizeof(u_int16_t) + \
			(sizeof(u_int8_t) * 2))
#endif  /* RSVP_OBJECT_HEADER_LENGTH */
/* RSVP Object Class */
enum rsvp_object_class{
	RSVP_OBJECT_SESSION         = 1,
#define RSVP_OBJECT_SESSION           RSVP_OBJECT_SESSION
#ifdef  RSVP_LENGTH_SESSION
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_SESSION!"
#	undef  RSVP_LENGTH_SESSION
#	define RSVP_LENGTH_SESSION   RSVP_OBJECT_HEADER_LENGTH + 8
#else   /* RSVP_LENGTH_SESSION */
#	define RSVP_LENGTH_SESSION   RSVP_OBJECT_HEADER_LENGTH + 8
#endif  /* RSVP_LENGTH_SESSION */
	RSVP_OBJECT_RESV_HOP        = 3,
#define RSVP_OBJECT_RESV_HOP          RSVP_OBJECT_RESV_HOP
#ifdef  RSVP_LENGTH_RESV_HOP
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_RESV_HOP!"
#	undef  RSVP_LENGTH_RESV_HOP
#	define RSVP_LENGTH_RESV_HOP   RSVP_OBJECT_HEADER_LENGTH + 8
#else   /* RSVP_LENGTH_RESV_HOP */
#	define RSVP_LENGTH_RESV_HOP   RSVP_OBJECT_HEADER_LENGTH + 8
#endif  /* RSVP_LENGTH_RESV_HOP */
	RSVP_OBJECT_INTEGRITY,
#define RSVP_OBJECT_INTEGRITY         RSVP_OBJECT_INTEGRITY
#ifdef  RSVP_LENGTH_INTEGRITY
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_INTEGRITY!"
#	undef  RSVP_LENGTH_INTEGRITY
#	define RSVP_LENGTH_INTEGRITY  RSVP_OBJECT_HEADER_LENGTH + 20
#else   /* RSVP_LENGTH_INTEGRITY */
#	define RSVP_LENGTH_INTEGRITY  RSVP_OBJECT_HEADER_LENGTH + 20
#endif  /* RSVP_LENGTH_INTEGRITY */
	RSVP_OBJECT_TIME_VALUES,
#define RSVP_OBJECT_TIME_VALUES       RSVP_OBJECT_TIME_VALUES
#ifdef  RSVP_LENGTH_TIME_VALUES
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_TIME_VALUES!"
#	undef  RSVP_LENGTH_TIME_VALUES
#	define RSVP_LENGTH_TIME_VALUES     RSVP_OBJECT_HEADER_LENGTH + 4
#else   /* RSVP_LENGTH_TIME_VALUES */
#	define RSVP_LENGTH_TIME_VALUES     RSVP_OBJECT_HEADER_LENGTH + 4
#endif  /* RSVP_LENGTH_TIME_VALUES */
	RSVP_OBJECT_ERROR_SPEC,
#define RSVP_OBJECT_ERROR_SPEC        RSVP_OBJECT_ERROR_SPEC
#ifdef  RSVP_LENGTH_ERROR_SPEC
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_ERROR_SPEC!"
#	undef  RSVP_LENGTH_ERROR_SPEC
#	define RSVP_LENGTH_ERROR_SPEC      RSVP_OBJECT_HEADER_LENGTH + 8
#else   /* RSVP_LENGTH_ERROR_SPEC */
#	define RSVP_LENGTH_ERROR_SPEC      RSVP_OBJECT_HEADER_LENGTH + 8
#endif  /* RSVP_LENGTH_ERROR_SPEC */
	RSVP_OBJECT_SCOPE,
#define RSVP_OBJECT_SCOPE             RSVP_OBJECT_SCOPE
#ifdef  RSVP_LENGTH_SCOPE
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_SCOPE!"
#	undef  RSVP_LENGTH_SCOPE
#	define RSVP_LENGTH_SCOPE(foo) \
			(RSVP_OBJECT_HEADER_LENGTH + \
			(foo * sizeof(in_addr_t)))
#else   /* RSVP_LENGTH_SCOPE */
#	define RSVP_LENGTH_SCOPE(foo) \
			(RSVP_OBJECT_HEADER_LENGTH + \
			(foo * sizeof(in_addr_t)))
#endif  /* RSVP_LENGTH_SCOPE */
	RSVP_OBJECT_STYLE,
#define RSVP_OBJECT_STYLE             RSVP_OBJECT_STYLE
#ifdef  RSVP_LENGTH_STYLE
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_STYLE!"
#	undef  RSVP_LENGTH_STYLE
#	define RSVP_LENGTH_STYLE      RSVP_OBJECT_HEADER_LENGTH + 4
#else   /* RSVP_LENGTH_STYLE */
#	define RSVP_LENGTH_STYLE      RSVP_OBJECT_HEADER_LENGTH + 4
#endif  /* RSVP_LENGTH_STYLE */
	RSVP_OBJECT_FLOWSPEC,
#define RSVP_OBJECT_FLOWSPEC          RSVP_OBJECT_FLOWSPEC
#ifdef  RSVP_LENGTH_FLOWSPEC
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_FLOWSPEC!"
#	undef  RSVP_LENGTH_FLOWSPEC
#	define RSVP_LENGTH_FLOWSPEC   RSVP_OBJECT_HEADER_LENGTH + 32
#else   /* RSVP_LENGTH_FLOWSPEC */
#	define RSVP_LENGTH_FLOWSPEC   RSVP_OBJECT_HEADER_LENGTH + 32
#endif  /* RSVP_LENGTH_FLOWSPEC */
	RSVP_OBJECT_FILTER_SPEC,
#define RSVP_OBJECT_FILTER_SPEC       RSVP_OBJECT_FILTER_SPEC
#ifdef  RSVP_LENGTH_FILTER_SPEC
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_FILTER_SPEC!"
#	undef  RSVP_LENGTH_FILTER_SPEC
#	define RSVP_LENGTH_FILTER_SPEC    RSVP_OBJECT_HEADER_LENGTH + 8
#else   /* RSVP_LENGTH_FILTER_SPEC */
#	define RSVP_LENGTH_FILTER_SPEC    RSVP_OBJECT_HEADER_LENGTH + 8
#endif  /* RSVP_LENGTH_FILTER_SPEC */
	RSVP_OBJECT_SENDER_TEMPLATE,
#define RSVP_OBJECT_SENDER_TEMPLATE   RSVP_OBJECT_SENDER_TEMPLATE
#ifdef  RSVP_LENGTH_SENDER_TEMPLATE
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_SENDER_TEMPLATE!"
#	undef  RSVP_LENGTH_SENDER_TEMPLATE
#	define RSVP_LENGTH_SENDER_TEMPLATE RSVP_OBJECT_HEADER_LENGTH + 8
#else   /* RSVP_LENGTH_SENDER_TEMPLATE */
#	define RSVP_LENGTH_SENDER_TEMPLATE RSVP_OBJECT_HEADER_LENGTH + 8
#endif  /* RSVP_LENGTH_SENDER_TEMPLATE */
	RSVP_OBJECT_SENDER_TSPEC,
#define RSVP_OBJECT_SENDER_TSPEC      RSVP_OBJECT_SENDER_TSPEC
#ifdef  RSVP_LENGTH_SENDER_TSPEC
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_SENDER_TSPEC!"
#	undef  RSVP_LENGTH_SENDER_TSPEC
#	define RSVP_LENGTH_SENDER_TSPEC    RSVP_OBJECT_HEADER_LENGTH + 8
#else   /* RSVP_LENGTH_SENDER_TSPEC */
#	define RSVP_LENGTH_SENDER_TSPEC    RSVP_OBJECT_HEADER_LENGTH + 8
#endif  /* RSVP_LENGTH_SENDER_TSPEC */
	RSVP_OBJECT_ADSPEC,
#define RSVP_OBJECT_ADSPEC            RSVP_OBJECT_ADSPEC
#ifdef  RSVP_LENGTH_ADSPEC
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_ADSPEC!"
#	undef  RSVP_LENGTH_ADSPEC
#	define RSVP_LENGTH_ADSPEC     RSVP_OBJECT_HEADER_LENGTH + ADSPEC_MESSAGE_HEADER
#else   /* RSVP_LENGTH_ADSPEC */
#	define RSVP_LENGTH_ADSPEC     RSVP_OBJECT_HEADER_LENGTH + ADSPEC_MESSAGE_HEADER
#endif  /* RSVP_LENGTH_ADSPEC */
	RSVP_OBJECT_POLICY_DATA,
#define RSVP_OBJECT_POLICY_DATA       RSVP_OBJECT_POLICY_DATA
	RSVP_OBJECT_RESV_CONFIRM,
#define RSVP_OBJECT_RESV_CONFIRM      RSVP_OBJECT_RESV_CONFIRM
#ifdef  RSVP_LENGTH_RESV_CONFIRM
#	warning "Sorry! The t50 is disabling RSVP_LENGTH_RESV_CONFIRM!"
#	undef  RSVP_LENGTH_RESV_CONFIRM
#	define RSVP_LENGTH_RESV_CONFIRM    RSVP_OBJECT_HEADER_LENGTH + 4
#else   /* RSVP_LENGTH_RESV_CONFIRM */
#	define RSVP_LENGTH_RESV_CONFIRM    RSVP_OBJECT_HEADER_LENGTH + 4
#endif  /* RSVP_LENGTH_RESV_CONFIRM */
	RSVP_OBJECT_MESSAGE_ID      = 23,
#define RSVP_OBJECT_MESSAGE_ID        RSVP_OBJECT_MESSAGE_ID
	RSVP_OBJECT_MESSAGE_ID_ACK,
#define RSVP_OBJECT_MESSAGE_ID_ACK    RSVP_OBJECT_MESSAGE_ID_ACK
	RSVP_OBJECT_MESSAGE_ID_NACK = RSVP_OBJECT_MESSAGE_ID_ACK,
#define RSVP_OBJECT_MESSAGE_ID_NACK   RSVP_OBJECT_MESSAGE_ID_NACK
};
/* RSVP TSPEC Class Service */
enum tspec_service{
#ifdef  TSPEC_MESSAGE_HEADER
#	warning "Sorry! The t50 is disabling TSPEC_MESSAGE_HEADER!"
#	undef  TSPEC_MESSAGE_HEADER
#	define TSPEC_MESSAGE_HEADER   4
#else   /* TSPEC_MESSAGE_HEADER */
#	define TSPEC_MESSAGE_HEADER   4
#endif  /* TSPEC_MESSAGE_HEADER */
	TSPEC_TRAFFIC_SERVICE       = 1,
#define TSPEC_TRAFFIC_SERVICE         TSPEC_TRAFFIC_SERVICE
	TSPEC_GUARANTEED_SERVICE,
#define TSPEC_GUARANTEED_SERVICE      TSPEC_GUARANTEED_SERVICE
#define TSPECT_TOKEN_BUCKET_SERVICE   127
#ifdef  TSPEC_TOKEN_BUCKET_LENGTH
#	warning "Sorry! The t50 is disabling TSPEC_TOKEN_BUCKET_LENGTH!"
#	undef  TSPEC_TOKEN_BUCKET_LENGTH
#	define TSPEC_TOKEN_BUCKET_LENGTH   24
#else   /* TSPEC_TOKEN_BUCKET_LENGTH */
#	define TSPEC_TOKEN_BUCKET_LENGTH   24
#endif  /* TSPEC_TOKEN_BUCKET_LENGTH */
#ifdef  TSPEC_SERVICES
#	warning "Sorry! The t50 is disabling TSPEC_SERVICES!"
#	undef  TSPEC_SERVICES
#	define TSPEC_SERVICES(foo) \
		(foo == TSPEC_TRAFFIC_SERVICE   || \
		 foo == TSPEC_GUARANTEED_SERVICE ? \
			TSPEC_TOKEN_BUCKET_LENGTH : \
		0)
#else   /* TSPEC_SERVICES */
#	define TSPEC_SERVICES(foo) \
		(foo == TSPEC_TRAFFIC_SERVICE   || \
		 foo == TSPEC_GUARANTEED_SERVICE ? \
			TSPEC_TOKEN_BUCKET_LENGTH : \
		0)
#endif  /* TSPEC_SERVICES */
};
/* RSVP ADSPEC Class Service */
enum adspec_service{
#ifdef  ADSPEC_MESSAGE_HEADER
#	warning "Sorry! The t50 is disabling ADSPEC_MESSAGE_HEADER!"
#	undef  ADSPEC_MESSAGE_HEADER
#	define ADSPEC_MESSAGE_HEADER  4
#else   /* ADSPEC_MESSAGE_HEADER */
#	define ADSPEC_MESSAGE_HEADER  4
#endif  /* ADSPEC_MESSAGE_HEADER */
#ifdef  ADSPEC_SERVDATA_HEADER
#	warning "Sorry! The t50 is disabling ADSPEC_SERVDATA_HEADER!"
#	undef  ADSPEC_SERVDATA_HEADER
#	define ADSPEC_SERVDATA_HEADER 4
#else   /* ADSPEC_SERVDATA_HEADER */
#	define ADSPEC_SERVDATA_HEADER 4
#endif  /* ADSPEC_SERVDATA_HEADER */
#ifdef  ADSPEC_PARAMETER_DATA
#	warning "Sorry! The t50 is disabling ADSPEC_PARAMETER_DATA!"
#	undef  ADSPEC_PARAMETER_DATA
#	define ADSPEC_PARAMETER_DATA  4
#else   /* ADSPEC_PARAMETER_DATA */
#	define ADSPEC_PARAMETER_DATA  4
#endif  /* ADSPEC_PARAMETER_DATA */
	ADSPEC_PARAMETER_SERVICE    = 1,
#define ADSPEC_PARAMETER_SERVICE      ADSPEC_PARAMETER_SERVICE
#ifdef  ADSPEC_PARAMETER_LENGTH
#	warning "Sorry! The t50 is disabling ADSPEC_PARAMETER_LENGTH!"
#	undef  ADSPEC_PARAMETER_LENGTH
#	define ADSPEC_PARAMETER_LENGTH \
			(ADSPEC_MESSAGE_HEADER   + \
			((ADSPEC_SERVDATA_HEADER + \
			ADSPEC_PARAMETER_DATA) * 4))
#else   /* ADSPEC_PARAMETER_LENGTH */
#	define ADSPEC_PARAMETER_LENGTH \
			(ADSPEC_MESSAGE_HEADER   + \
			((ADSPEC_SERVDATA_HEADER + \
			ADSPEC_PARAMETER_DATA) * 4))
#endif  /* ADSPEC_PARAMETER_LENGTH */
#ifdef  ADSPEC_PARAMETER_ISHOPCNT
#	warning "Sorry! The t50 is disabling ADSPEC_PARAMETER_ISHOPCNT!"
#	undef  ADSPEC_PARAMETER_ISHOPCNT
#	define ADSPEC_PARAMETER_ISHOPCNT   4
#else   /* ADSPEC_PARAMETER_ISHOPCNT */
#	define ADSPEC_PARAMETER_ISHOPCNT   4
#endif  /* ADSPEC_PARAMETER_ISHOPCNT */
#ifdef  ADSPEC_PARAMETER_BANDWIDTH
#	warning "Sorry! The t50 is disabling ADSPEC_PARAMETER_BANDWIDTH!"
#	undef  ADSPEC_PARAMETER_BANDWIDTH
#	define ADSPEC_PARAMETER_BANDWIDTH  6
#else   /* ADSPEC_PARAMETER_BANDWIDTH */
#	define ADSPEC_PARAMETER_BANDWIDTH  6
#endif  /* ADSPEC_PARAMETER_BANDWIDTH */
#ifdef  ADSPEC_PARAMETER_LATENCY
#	warning "Sorry! The t50 is disabling ADSPEC_PARAMETER_LATENCY!"
#	undef  ADSPEC_PARAMETER_LATENCY
#	define ADSPEC_PARAMETER_LATENCY    8
#else   /* ADSPEC_PARAMETER_LATENCY */
#	define ADSPEC_PARAMETER_LATENCY    8
#endif  /* ADSPEC_PARAMETER_LATENCY */
#ifdef  ADSPEC_PARAMETER_COMPMTU
#	warning "Sorry! The t50 is disabling ADSPEC_PARAMETER_COMPMTU!"
#	undef  ADSPEC_PARAMETER_COMPMTU
#	define ADSPEC_PARAMETER_COMPMTU    10
#else   /* ADSPEC_PARAMETER_COMPMTU */
#	define ADSPEC_PARAMETER_COMPMTU    10
#endif  /* ADSPEC_PARAMETER_COMPMTU */
	ADSPEC_GUARANTEED_SERVICE,
#define ADSPEC_GUARANTEED_SERVICE     ADSPEC_GUARANTEED_SERVICE
#ifdef  ADSPEC_GUARANTEED_LENGTH
#	warning "Sorry! The t50 is disabling ADSPEC_GUARANTEED_LENGTH!"
#	undef  ADSPEC_GUARANTEED_LENGTH
#	define ADSPEC_GUARANTEED_LENGTH \
			(ADSPEC_MESSAGE_HEADER   + \
			((ADSPEC_SERVDATA_HEADER + \
			ADSPEC_PARAMETER_DATA) * 4))
#else   /* ADSPEC_GUARANTEED_LENGTH */
#	define ADSPEC_GUARANTEED_LENGTH \
			(ADSPEC_MESSAGE_HEADER   + \
			((ADSPEC_SERVDATA_HEADER + \
			ADSPEC_PARAMETER_DATA) * 4))
#endif  /* ADSPEC_GUARANTEED_LENGTH */
	ADSPEC_CONTROLLED_SERVICE   = 5,
#define ADSPEC_CONTROLLED_SERVICE     ADSPEC_CONTROLLED_SERVICE
#define ADSPEC_CONTROLLED_LENGTH      ADSPEC_MESSAGE_HEADER
#ifdef  ADSPEC_SERVICES
#	warning "Sorry! The t50 is disabling ADSPEC_SERVICES!"
#	undef  ADSPEC_SERVICES
#	define ADSPEC_SERVICES(foo) \
			(ADSPEC_PARAMETER_LENGTH + \
			(foo == ADSPEC_CONTROLLED_SERVICE || \
			 foo == ADSPEC_GUARANTEED_SERVICE  ? \
				ADSPEC_GUARANTEED_LENGTH : \
			0) + \
			(foo == ADSPEC_CONTROLLED_SERVICE ? \
				ADSPEC_CONTROLLED_LENGTH : \
			0))
#else   /* ADSPEC_SERVICES */
#	define ADSPEC_SERVICES(foo) \
			(ADSPEC_PARAMETER_LENGTH + \
			(foo == ADSPEC_CONTROLLED_SERVICE || \
			 foo == ADSPEC_GUARANTEED_SERVICE  ? \
				ADSPEC_GUARANTEED_LENGTH : \
			0) + \
			(foo == ADSPEC_CONTROLLED_SERVICE ? \
				ADSPEC_CONTROLLED_LENGTH : \
			0))
#endif  /* ADSPEC_SERVICES */
};


/* RSVP PROTOCOL STRUCTURES

   RSVP protocol structures used by code.
   Any new RSVP protocol structure should be added in this section. */
/*
 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
 *
 * 3.1.1 Common Header
 *
 *          0             1              2             3
 *   +-------------+-------------+-------------+-------------+
 *   | Vers | Flags|  Msg Type   |       RSVP Checksum       |
 *   +-------------+-------------+-------------+-------------+
 *   |  Send_TTL   | (Reserved)  |        RSVP Length        |
 *   +-------------+-------------+-------------+-------------+
 */
struct rsvp_common_hdr{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int16_t flags:4,                /* flags                       */
	          version:4,              /* version                     */
	          type:8;                 /* message type                */
#elif defined(__BIG_ENDIAN_BITFIELD)
	u_int16_t version:4,              /* version                     */
	          flags:4,                /* flags                       */
	          type:8;                 /* message type                */
#else
#	error	"Adjust your <asm/byteorder.h> defines"
#endif
	u_int16_t check;                  /* checksum                    */
	u_int8_t  ttl;                    /* time to live                */
	u_int8_t  reserved;               /* reserved                    */
	u_int16_t length;                 /* message length              */
};


/* Function Name: RSVP objects size claculation.

   Description:   This function calculates the size of RSVP objects.

   Targets:       N/A */
__inline__ static size_t rsvp_objects_len(const u_int8_t foo, const u_int8_t bar, const u_int8_t baz, const u_int8_t qux){
	static size_t size;

	/*
	 * The code starts with the size of SESSION Object Class  (according
	 * to the RFC 2205, this is required in every RSVP message), and, if
	 * the appropriate RSVP Message type matches,  size  accumulates the
	 * corresponded Object Class(s)  size  to build the appropriate RSVP 
	 * message.  Otherwise,   it just returns the size of SESSION Object
	 * Class.
	 */
	size = RSVP_LENGTH_SESSION;

	/* 
	 * The RESV_HOP Object Class is present for the following:
	 * 3.1.3 Path Messages
	 * 3.1.4 Resv Messages
	 * 3.1.5 Path Teardown Messages
	 * 3.1.6 Resv Teardown Messages
	 * 3.1.8 Resv Error Messages
	 */
	if(foo == RSVP_MESSAGE_TYPE_PATH     ||
	   foo == RSVP_MESSAGE_TYPE_RESV     ||
	   foo == RSVP_MESSAGE_TYPE_PATHTEAR ||
	   foo == RSVP_MESSAGE_TYPE_RESVTEAR ||
	   foo == RSVP_MESSAGE_TYPE_RESVERR)
		size += RSVP_LENGTH_RESV_HOP;

	/* 
	 * The TIME_VALUES Object Class is present for the following:
	 * 3.1.3 Path Messages
	 * 3.1.4 Resv Messages
	 */
	if(foo == RSVP_MESSAGE_TYPE_PATH ||
	   foo == RSVP_MESSAGE_TYPE_RESV)
		size += RSVP_LENGTH_TIME_VALUES;

	/* 
	 * The ERROR_SPEC Object Class is present for the following:
	 * 3.1.5 Path Teardown Messages
	 * 3.1.8 Resv Error Messages
	 * 3.1.9 Confirmation Messages
	 */
	if(foo == RSVP_MESSAGE_TYPE_PATHERR ||
	   foo == RSVP_MESSAGE_TYPE_RESVERR ||
	   foo == RSVP_MESSAGE_TYPE_RESVCONF)
		size += RSVP_LENGTH_ERROR_SPEC;

	/* 
	 * The SENDER_TEMPLATE,  SENDER_TSPEC and  ADSPEC Object Classes are
	 * present for the following:
	 * 3.1.3 Path Messages
	 * 3.1.5 Path Teardown Messages
	 * 3.1.7 Path Error Messages
	 */
	if(foo == RSVP_MESSAGE_TYPE_PATH     ||
	   foo == RSVP_MESSAGE_TYPE_PATHTEAR ||
	   foo == RSVP_MESSAGE_TYPE_PATHERR){
		size += RSVP_LENGTH_SENDER_TEMPLATE;
		size += RSVP_LENGTH_SENDER_TSPEC;
		size += TSPEC_SERVICES(qux);
		size += RSVP_LENGTH_ADSPEC;
		size += ADSPEC_SERVICES(baz);
	}

	/* 
	 * The RESV_CONFIRM Object Class is present for the following:
	 * 3.1.4 Resv Messages
	 * 3.1.9 Confirmation Messages
	 */
	if(foo == RSVP_MESSAGE_TYPE_RESV ||
	   foo == RSVP_MESSAGE_TYPE_RESVCONF)
		size += RSVP_LENGTH_RESV_CONFIRM;

	/* 
	 * The STYLE Object Classes is present for the following:
	 * 3.1.4 Resv Messages
	 * 3.1.6 Resv Teardown Messages
	 * 3.1.8 Resv Error Messages
	 * 3.1.9 Confirmation Messages
	 */
	if(foo == RSVP_MESSAGE_TYPE_RESV     ||
	   foo == RSVP_MESSAGE_TYPE_RESVTEAR ||
	   foo == RSVP_MESSAGE_TYPE_RESVERR  ||
	   foo == RSVP_MESSAGE_TYPE_RESVCONF){
		/* 
		 * The SCOPE Object Classes is present for the following:
		 * 3.1.4 Resv Messages
		 * 3.1.6 Resv Teardown Messages
		 * 3.1.8 Resv Error Messages
		 */
		if(foo == RSVP_MESSAGE_TYPE_RESV     ||
		   foo == RSVP_MESSAGE_TYPE_RESVTEAR ||
		   foo == RSVP_MESSAGE_TYPE_RESVERR)
			size += RSVP_LENGTH_SCOPE(bar);

		size += RSVP_LENGTH_STYLE;
	}	

	return(size);
}


__END_DECLS


#ifdef __cplusplus
}
#endif


#endif  /* __RSVP_H */
