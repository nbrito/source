/* 
 * $Id: gre.h,v 5.5 2011-03-11 11:17:19-03 nbrito Exp $
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
#ifndef __GRE_H
#define __GRE_H 1


/* GLOBAL HEADERS/INCLUDES

   Global headers/includes used by code.
   Any new global headers/includes should be added in this section. */
#include <common.h>


#ifdef __cplusplus
extern "C" {
#endif


__BEGIN_DECLS


/* GLOBAL GRE PROTOCOL DEFINITIONS

   Global GRE protocol definitions used by code.
   Any new global GRE protocol definition should be added in this section. */
#ifdef  GREVERSION
#	warning "Sorry! The t50 is disabling GREVERSION!"
#	undef  GREVERSION
#	define GREVERSION             0
#else   /* GREVERSION */
#	define GREVERSION             0
#endif  /* GREVERSION */
/* GRE Options */
enum gre_option{
	GRE_OPTION_STRICT           = 0x01,
#define GRE_OPTION_STRICT             GRE_OPTION_STRICT
	GRE_OPTION_SEQUENCE         = 0x02,
#define GRE_OPTION_SEQUENCE           GRE_OPTION_SEQUENCE
#ifdef  GRE_OPTLEN_SEQUENCE
#	warning "Sorry! The t50 is disabling GRE_OPTLEN_SEQUENCE!"
#	undef  GRE_OPTLEN_SEQUENCE
#	define GRE_OPTLEN_SEQUENCE    sizeof (struct gre_seq_hdr)
#else   /* GRE_OPTLEN_SEQUENCE */
#	define GRE_OPTLEN_SEQUENCE    sizeof (struct gre_seq_hdr)
#endif  /* GRE_OPTLEN_SEQUENCE */
	GRE_OPTION_KEY              = 0x04,
#define GRE_OPTION_KEY                GRE_OPTION_KEY
#ifdef  GRE_OPTLEN_KEY
#	warning "Sorry! The t50 is disabling GRE_OPTLEN_KEY!"
#	undef  GRE_OPTLEN_KEY
#	define GRE_OPTLEN_KEY         sizeof(struct gre_key_hdr)
#else   /* GRE_OPTLEN_KEY */
#	define GRE_OPTLEN_KEY         sizeof(struct gre_key_hdr)
#endif  /* GRE_OPTLEN_KEY */
	GRE_OPTION_ROUTING          = 0x08,
#define GRE_OPTION_ROUTING            GRE_OPTION_ROUTING
	GRE_OPTION_CHECKSUM         = 0x10,
#define GRE_OPTION_CHECKSUM           GRE_OPTION_CHECKSUM
#ifdef  GRE_OPTLEN_CHECKSUM
#	warning "Sorry! The t50 is disabling GRE_OPTLEN_CHECKSUM!"
#	undef  GRE_OPTLEN_CHECKSUM
#	define GRE_OPTLEN_CHECKSUM    sizeof(struct gre_sum_hdr)
#else   /* GRE_OPTLEN_CHECKSUM */
#	define GRE_OPTLEN_CHECKSUM    sizeof(struct gre_sum_hdr)
#endif  /* GRE_OPTLEN_CHECKSUM */
};


/* GRE PROTOCOL STRUCTURES

   GRE protocol structures used by code.
   Any new GRE protocol structure should be added in this section. */
/*
 * Generic Routing Encapsulation (GRE) (RFC 1701)
 *
 *   The GRE packet header has form:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |      Checksum (optional)      |       Offset (optional)       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Key (optional)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Sequence Number (optional)                 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Routing (optional)
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Key and Sequence Number Extensions to GRE (RFC 2890)
 *
 *   The proposed GRE header will have the following format:
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |C| |K|S| Reserved0       | Ver |         Protocol Type         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |      Checksum (optional)      |       Reserved1 (Optional)    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Key (optional)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 Sequence Number (Optional)                    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct gre_hdr{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int16_t recur:3,                /* recursion control           */
	          s:1,                    /* strict source route         */
	          S:1,                    /* sequence number present     */
	          K:1,                    /* key present                 */
	          R:1,                    /* routing present             */
	          C:1,                    /* checksum present            */
	          version:3,              /* version                     */
	          flags:5;                /* flags                       */
#elif defined(__BIG_ENDIAN_BITFIELD)
	u_int16_t C:1,                    /* checksum present            */
	          R:1,                    /* routing present             */
	          K:1,                    /* key present                 */
	          S:1,                    /* sequence number present     */
	          s:1,                    /* strict source route         */
	          recur:3,                /* recursion control           */
	          flags:5,                /* flags                       */
	          version:3;              /* version                     */
#else
#	error	"Adjust your <asm/byteorder.h> defines"
#endif
	u_int16_t proto;                  /* protocol                    */
	u_int8_t  __optional[0];          /* optional                    */
};
/*
 * Generic Routing Encapsulation (GRE) (RFC 1701)
 *
 *    Offset (2 octets)
 *
 *    The  offset  field  indicates  the octet offset from the start of the
 *    Routing  field  to  the  first octet of the active Source Route Entry
 *    to be examined.  This  field  is  present  if  the Routing Present or
 *    the Checksum Present bit is set to 1, and contains valid  information
 *    only if the Routing Present bit is set to 1.
 *
 *    Checksum (2 octets)
 *
 *    The Checksum  field  contains the IP (one's complement)  checksum  of
 *    the GRE  header  and  the  payload  packet.  This field is present if
 *    the  Routing  Present  or  the  Checksum Present bit is set to 1, and
 *    contains  valid  information  only if the Checksum Present bit is set
 *    to 1.
 */
struct gre_sum_hdr{
	u_int16_t check;                  /* checksum                    */
	u_int16_t offset;                 /* offset                      */
};
/*
 * Generic Routing Encapsulation (GRE) (RFC 1701)
 *
 *    Key (4 octets)
 *
 *    The  Key  field  contains  a  four octet number which was inserted by
 *    the encapsulator.  It may be used by the receiver to authenticate the
 *    source of the packet. The techniques for determining authenticity are
 *    outside of the scope of this document.  The Key field is only present
 *    if the Key Present field is set to 1.
 */
struct gre_key_hdr{
	u_int32_t key;                    /* key                         */
};
/*
 * Generic Routing Encapsulation (GRE) (RFC 1701)
 *
 *    Sequence Number (4 octets)
 *
 *    The Sequence Number  field  contains an unsigned 32 bit integer which
 *    is inserted by  the  encapsulator.  It may be used by the receiver to
 *    establish the  order  in which packets have been transmitted from the
 *    encapsulator to the receiver. The exact algorithms for the generation
 *    of  the  Sequence  Number  and  the  semantics  of their reception is 
 *    outside of the scope of this document.
 */
struct gre_seq_hdr{
	u_int32_t sequence;          /* sequence number             */
};	

/* Function Name: GRE header size calculation.

   Description:   This function calculates the size of GRE header.

   Targets:       N/A */
__inline__ static size_t gre_opt_len(const u_int8_t foo, const u_int8_t bar){
	static size_t size;

	/*
	 * The code starts with size '0' and it accumulates all the required
	 * size if the conditionals match. Otherwise, it returns size '0'.
	 */
	size = 0;

	/*
	 * Returns the size of the entire  GRE  packet  only in the case  of
	 * encapsulation has been defined ('--encapsulated').
	 */
	if(bar){
		/*
		 * First thing is to accumulate GRE Header size.
		 */
		size += sizeof(struct gre_hdr);

		/*
		 * Checking whether add OPTIONAL header size.
		 *
		 * CHECKSUM HEADER?
		 */
		if((foo & GRE_OPTION_CHECKSUM) == GRE_OPTION_CHECKSUM)
			size += GRE_OPTLEN_CHECKSUM;
		/* KEY HEADER? */
		if((foo & GRE_OPTION_KEY) == GRE_OPTION_KEY)
			size += GRE_OPTLEN_KEY;
		/* SEQUENCE HEADER? */
		if((foo & GRE_OPTION_SEQUENCE) == GRE_OPTION_SEQUENCE)
			size += GRE_OPTLEN_SEQUENCE;

		/*
		 * Accumulating an extra IP Header size.
		 */
		size += sizeof(struct iphdr);
	}

	return(size);
}


__END_DECLS


#ifdef __cplusplus
}
#endif


#endif  /* __GRE_H */
