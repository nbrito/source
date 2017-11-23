/* 
 * $Id: eigrp.h,v 5.4 2011-03-09 19:32:20-03 nbrito Exp $
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
#ifndef __EIGRP_H
#define __EIGRP_H 1


/* GLOBAL HEADERS/INCLUDES

   Global headers/includes used by code.
   Any new global headers/includes should be added in this section. */
#include <common.h>


#ifdef __cplusplus
extern "C" {
#endif


__BEGIN_DECLS


/* GLOBAL EIGRP PROTOCOL DEFINITIONS

   Global EIGRP protocol definitions used by code.
   Any new global EIGRP protocol definition should be added in this section. */
#ifdef  IPPROTO_EIGRP
#	warning "Sorry! The t50 is disabling IPPROTO_EIGRP!"
#	undef  IPPROTO_EIGRP
#	define IPPROTO_EIGRP          88
#else   /* IPPROTO_EIGRP */
#	define IPPROTO_EIGRP          88
#endif  /* IPPROTO_EIGRP */
#ifdef  EIGRPVERSION
#	warning "Sorry! The t50 is disabling EIGRPVERSION!"
#	undef  EIGRPVERSION
#	define EIGRPVERSION           2
#else   /* EIGRPVERSION */
#	define EIGRPVERSION           2
#endif  /* EIGRPVERSION */
#ifdef  EIGRP_FLAG_INIT
#	undef   EIGRP_FLAG_INIT
#	define  EIGRP_FLAG_INIT       0x00000001
#else   /* EIGRP_FLAG_INIT */
#	define  EIGRP_FLAG_INIT       0x00000001
#endif  /* EIGRP_FLAG_INIT */
#ifdef  EIGRP_FLAG_COND
#	undef   EIGRP_FLAG_COND
#	define  EIGRP_FLAG_COND       0x00000002
#else   /* EIGRP_FLAG_COND */
#	define  EIGRP_FLAG_COND       0x00000002
#endif  /* EIGRP_FLAG_INIT */
/* EIGRP Message Opcode */
enum eigrp_opcode{
	EIGRP_OPCODE_UPDATE         = 1,
#define EIGRP_OPCODE_UPDATE           EIGRP_OPCODE_UPDATE
	EIGRP_OPCODE_REQUEST,
#define EIGRP_OPCODE_REQUEST          EIGRP_OPCODE_REQUEST
	EIGRP_OPCODE_QUERY,
#define EIGRP_OPCODE_QUERY            EIGRP_OPCODE_QUERY
	EIGRP_OPCODE_REPLY,
#define EIGRP_OPCODE_REPLY            EIGRP_OPCODE_REPLY
	EIGRP_OPCODE_HELLO,
#define EIGRP_OPCODE_HELLO            EIGRP_OPCODE_HELLO
	EIGRP_OPCODE_IPX_SAP,
#define EIGRP_OPCODE_IPX_SAP          EIGRP_OPCODE_IPX_SAP
};
/* EIGRP Message Type/Length/Value */
enum eigrp_tlv{
	EIGRP_TYPE_PARAMETER        = 0x0001,
#define EIGRP_TYPE_PARAMETER          EIGRP_TYPE_PARAMETER
#ifdef  EIGRP_TLEN_PARAMETER
#	warning "Sorry! The t50 is disabling EIGRP_TLEN_PARAMETER!"
#	undef  EIGRP_TLEN_PARAMETER
#	define EIGRP_TLEN_PARAMETER   12
#else   /* EIGRP_TLEN_PARAMETER */
#	define EIGRP_TLEN_PARAMETER   12
#endif  /* EIGRP_TLEN_PARAMETER */
	EIGRP_TYPE_AUTH,
#define EIGRP_TYPE_AUTH               EIGRP_TYPE_AUTH
#ifdef  EIGRP_TLEN_AUTH
#	warning "Sorry! The t50 is disabling EIGRP_TLEN_AUTH!"
#	undef  EIGRP_TLEN_AUTH
#	define EIGRP_TLEN_AUTH        40
#else   /* EIGRP_TLEN_AUTH */
#	define EIGRP_TLEN_AUTH        40
#endif  /* EIGRP_TLEN_AUTH */
#ifdef  EIGRP_PADDING_BLOCK
#	warning "Sorry! The t50 is disabling EIGRP_PADDING_BLOCK!"
#	undef  EIGRP_PADDING_BLOCK
#	define EIGRP_PADDING_BLOCK    12
#else   /* EIGRP_PADDING_BLOCK */
#	define EIGRP_PADDING_BLOCK    12
#endif  /* EIGRP_PADDING_BLOCK */
#ifdef  EIGRP_MAXIMUM_KEYID
#	warning "Sorry! The t50 is disabling EIGRP_MAXIMUM_KEYID!"
#	undef  EIGRP_MAXIMUM_KEYID
#	define EIGRP_MAXIMUM_KEYID    2147483647
#else   /* EIGRP_MAXIMUM_KEYID */
#	define EIGRP_MAXIMUM_KEYID    2147483647
#endif  /* EIGRP_MAXIMUM_KEYID */
	EIGRP_TYPE_SEQUENCE,
#define EIGRP_TYPE_SEQUENCE           EIGRP_TYPE_SEQUENCE
#ifdef  EIGRP_TLEN_SEQUENCE
#	warning "Sorry! The t50 is disabling EIGRP_TLEN_SEQUENCE!"
#	undef  EIGRP_TLEN_SEQUENCE
#	define EIGRP_TLEN_SEQUENCE    9
#else   /* EIGRP_TLEN_SEQUENCE */
#	define EIGRP_TLEN_SEQUENCE    9
#endif  /* EIGRP_TLEN_SEQUENCE */
	EIGRP_TYPE_SOFTWARE,
#define EIGRP_TYPE_SOFTWARE           EIGRP_TYPE_SOFTWARE
#ifdef  EIGRP_TLEN_SOFTWARE
#	warning "Sorry! The t50 is disabling EIGRP_TLEN_SOFTWARE!"
#	undef  EIGRP_TLEN_SOFTWARE
#	define EIGRP_TLEN_SOFTWARE    8
#else   /* EIGRP_TLEN_SOFTWARE */
#	define EIGRP_TLEN_SOFTWARE    8
#endif  /* EIGRP_TLEN_SOFTWARE */
	EIGRP_TYPE_MULTICAST,
#define EIGRP_TYPE_MULTICAST          EIGRP_TYPE_MULTICAST
#ifdef  EIGRP_TLEN_MULTICAST
#	warning "Sorry! The t50 is disabling EIGRP_TLEN_MULTICAST!"
#	undef  EIGRP_TLEN_MULTICAST
#	define EIGRP_TLEN_MULTICAST   8
#else   /* EIGRP_TLEN_MULTICAST */
#	define EIGRP_TLEN_MULTICAST   8
#endif  /* EIGRP_TLEN_MULTICAST */
	EIGRP_TYPE_INTERNAL         = 0x0102,
#define EIGRP_TYPE_INTERNAL           EIGRP_TYPE_INTERNAL
#ifdef  EIGRP_TLEN_INTERNAL
#	warning "Sorry! The t50 is disabling EIGRP_TLEN_INTERNAL!"
#	undef  EIGRP_TLEN_INTERNAL
#	define EIGRP_TLEN_INTERNAL    25
#else   /* EIGRP_TLEN_INTERNAL */
#	define EIGRP_TLEN_INTERNAL    25
#endif  /* EIGRP_TLEN_INTERNAL */
	EIGRP_TYPE_EXTERNAL         = 0x0103,
#define EIGRP_TYPE_EXTERNAL           EIGRP_TYPE_EXTERNAL
#ifdef  EIGRP_TLEN_EXTERNAL
#	warning "Sorry! The t50 is disabling EIGRP_TLEN_EXTERNAL!"
#	undef  EIGRP_TLEN_EXTERNAL
#	define EIGRP_TLEN_EXTERNAL    45
#else   /* EIGRP_TLEN_EXTERNAL */
#	define EIGRP_TLEN_EXTERNAL    45
#endif  /* EIGRP_TLEN_EXTERNAL */
#ifdef  EIGRP_DADDR_BUILD
#	warning "Sorry! The t50 is disabling EIGRP_DADDR_BUILD!"
#	undef  EIGRP_DADDR_BUILD
#	define EIGRP_DADDR_BUILD(foo, bar) \
			(foo &= htonl(~(0xffffffff >> ((bar >> 3) * 8))))
#else   /* EIGRP_DADDR_BUILD */
#	define EIGRP_DADDR_BUILD(foo, bar) \
			(foo &= htonl(~(0xffffffff >> ((bar >> 3) * 8))))
#endif  /* EIGRP_DADDR_BUILD */
#ifdef  EIGRP_DADDR_LENGTH
#	warning "Sorry! The t50 is disabling EIGRP_DADDR_LENGTH!"
#	undef  EIGRP_DADDR_LENGTH
#	define EIGRP_DADDR_LENGTH(foo) \
			(((foo >> 3) & 3) + (foo % 8 ? 1 : 0))
#else   /* EIGRP_DADDR_LENGTH */
#	define EIGRP_DADDR_LENGTH(foo) \
			(((foo >> 3) & 3) + (foo % 8 ? 1 : 0))
#endif  /* EIGRP_DADDR_LENGTH */
};
/* EIGRP K Values bitmask */
enum eigrp_kvalue_bitmask{
	EIGRP_KVALUE_K1             = 0x01,
#define EIGRP_KVALUE_K1               EIGRP_KVALUE_K1
	EIGRP_KVALUE_K2             = 0x02,
#define EIGRP_KVALUE_K2               EIGRP_KVALUE_K2
	EIGRP_KVALUE_K3             = 0x04,
#define EIGRP_KVALUE_K3               EIGRP_KVALUE_K3
	EIGRP_KVALUE_K4             = 0x08,
#define EIGRP_KVALUE_K4               EIGRP_KVALUE_K4
	EIGRP_KVALUE_K5             = 0x10,
#define EIGRP_KVALUE_K5               EIGRP_KVALUE_K5
};
/* EIGRP PROTOCOL STRUCTURES

   EIGRP protocol structures used by code.
   Any new EIGRP protocol structure should be added in this section. */
/*
 * Enhanced Interior Gateway Routing Protocol (EIGRP)
 *
 *    0                   1                   2                   3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Version    |    Opcode     |           Checksum            |
 *   +---------------+---------------+-------------------------------+
 *   |                             Flags                             |
 *   +-------------------------------+-------------------------------+
 *   |                        Sequence Number                        |
 *   +---------------------------------------------------------------+
 *   |                     Acknowledgment Number                     |
 *   +---------------------------------------------------------------+
 *   |                   Autonomous System Number                    |
 *   +---------------------------------------------------------------+
 *   |                                                               |
 *   //                  TLV (Type/Length/Value)                    //
 *   |                                                               |
 *   +---------------------------------------------------------------+
 *
 * Please,  be advised that there is no deep information about EIGRP,  no
 * other than EIGRP PCAP files public available.  Due to that I have done
 * a deep analysis using live EIGRP PCAP files to build the EIGRP Packet.
 *
 * There are some really good resources, such as:
 * http://www.protocolbase.net/protocols/protocol_EIGRP.php
 * http://packetlife.net/captures/category/cisco-proprietary/
 * http://oreilly.com/catalog/iprouting/chapter/ch04.html
 */
struct eigrp_hdr{
	u_int16_t version:8,              /* version                     */
	          opcode:8;               /* opcode                      */
	u_int16_t check;                  /* checksum                    */
	u_int32_t flags;                  /* flags                       */
	u_int32_t sequence;               /* sequence number             */
	u_int32_t acknowledge;            /* acknowledgment sequence #   */
	u_int32_t as;                     /* autonomous system           */
	u_int8_t  __tlv[0];               /* TLV (Type/Length/Value)     */
};


/* Function Name: EIGRP header size calculation.

   Description:   This function calculates the size of EIGRP header.

   Targets:       N/A */
__inline__ static size_t eigrp_hdr_len(const u_int16_t foo, const u_int16_t bar, const u_int8_t baz, const u_int32_t qux){
	static size_t size;

	/*
	 * The code starts with size '0' and it accumulates all the required
	 * size if the conditionals match. Otherwise, it returns size '0'.
	 */
	size = 0;

	/*
	 * The Authentication Data TVL must be used only in some cases:
	 * 1. IP Internal or External Routes TLV for Update
	 * 2. Software Version with Parameter TLVs for Hello
	 * 3. Next Multicast Sequence TLV for Hello
	 */
	if(qux)
		if(foo == EIGRP_OPCODE_UPDATE  ||
		  (foo == EIGRP_OPCODE_HELLO   &&
		  (bar == EIGRP_TYPE_MULTICAST ||
		   bar == EIGRP_TYPE_SOFTWARE)))
			size += EIGRP_TLEN_AUTH;
	/*
	 * AFAIK,   there are differences when building the EIGRP packet for
	 * Update, Request, Query and Reply.  Any EIGRP PCAP file I saw does
	 * not carry Parameter,  Software Version and/or Multicast Sequence,
	 * instead, it carries Authentication Data, IP Internal and External
	 * Routes or nothing (depends on the EIGRP Type).
	 */
	if(foo == EIGRP_OPCODE_UPDATE   ||
	   foo == EIGRP_OPCODE_REQUEST  ||
	   foo == EIGRP_OPCODE_QUERY    ||
	   foo == EIGRP_OPCODE_REPLY){
		/*
		 * For both Internal and External Routes TLV the code must perform
		 * an additional step to compute the EIGRP header length,  because 
		 * it depends on the the EIGRP Prefix, and it can be 1-4 octets.
		 */
		if(bar == EIGRP_TYPE_INTERNAL){
			size += EIGRP_TLEN_INTERNAL;
			size += EIGRP_DADDR_LENGTH(baz);
		}else if(bar == EIGRP_TYPE_EXTERNAL){
			size += EIGRP_TLEN_EXTERNAL;
			size += EIGRP_DADDR_LENGTH(baz);
		}
	/*
	 * In the other hand,   EIGRP Packet for Hello can carry Parameter, 
	 * Software Version, Multicast Sequence or nothing (Acknowledge).
	 */
	}else if (foo == EIGRP_OPCODE_HELLO){
		/*
		 * AFAIK,  EIGRP TLVs must follow a predefined sequence in order to
		 * be built. I am not sure whether any TLV's precedence will impact
		 * in the routers'  processing of  EIGRP Packet,  so I am following 
		 * exactly what I saw on live  EIGRP PCAP files.  Read the code and
		 * you will understand what I am talking about.
		 */
		switch(bar){
			case EIGRP_TYPE_MULTICAST:
				size += EIGRP_TLEN_MULTICAST;
				size += EIGRP_TLEN_SEQUENCE;
			case EIGRP_TYPE_SOFTWARE:
				size += EIGRP_TLEN_SOFTWARE;
			case EIGRP_TYPE_PARAMETER:
				size += EIGRP_TLEN_PARAMETER;
				break;
			default:
				break;
		}
	}

	return(size);
}


__END_DECLS


#ifdef __cplusplus
}
#endif


#endif  /* __EIGRP_H */
