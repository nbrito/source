/* 
 * $Id: rip.h,v 5.3 2011-03-09 19:32:20-03 nbrito Exp $
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
#ifndef __RIP_H
#define __RIP_H 1


/* GLOBAL HEADERS/INCLUDES

   Global headers/includes used by code.
   Any new global headers/includes should be added in this section. */
#include <common.h>


#ifdef __cplusplus
extern "C" {
#endif


__BEGIN_DECLS


/* GLOBAL RIP PROTOCOL DEFINITIONS

   Global RIP protocol definitions used by code.
   Any new global RIP protocol definition should be added in this section. */
#ifdef  IPPORT_RIP
#	warning "Sorry! The t50 is disabling IPPORT_RIP!"
#	undef  IPPORT_RIP
#	define IPPORT_RIP             520
#else   /* IPPORT_RIP */
#	define IPPORT_RIP             520
#endif  /* IPPORT_RIP */
#if     (RIPv1_C__)
#	ifdef  RIPVERSION
#		warning "Sorry! The t50 is disabling RIPVERSION!"
#		undef  RIPVERSION
#		define RIPVERSION     1
#	else   /* RIPVERSION */
#		define RIPVERSION     1
#	endif  /* RIPVERSION */
#elif   (RIPv2_C__)
#	ifdef  RIPVERSION
#		warning "Sorry! The t50 is disabling RIPVERSION!"
#		undef  RIPVERSION
#		define RIPVERSION     2
#	else   /* RIPVERSION */
#		define RIPVERSION     2
#	endif  /* RIPVERSION */
#endif  /* (RIPv1_C_) / (RIPv2_C__) */
#ifdef  RIP_HEADER_LENGTH
#	warning "Sorry! The t50 is disabling RIP_HEADER_LENGTH!"
#	undef  RIP_HEADER_LENGTH
#	define RIP_HEADER_LENGTH      4
#else   /* RIP_HEADER_LENGTH */
#	define RIP_HEADER_LENGTH      4
#endif  /* RIP_HEADER_LENGTH */
#ifdef  RIP_MESSAGE_LENGTH
#	warning "Sorry! The t50 is disabling RIP_MESSAGE_LENGTH!"
#	undef  RIP_MESSAGE_LENGTH
#	define RIP_MESSAGE_LENGTH     20
#else   /* RIP_MESSAGE_LENGTH */
#	define RIP_MESSAGE_LENGTH     20
#endif  /* RIP_MESSAGE_LENGTH */
#ifdef  RIP_AUTH_LENGTH
#	warning "Sorry! The t50 is disabling RIP_AUTH_LENGTH!"
#	undef  RIP_AUTH_LENGTH
#	define RIP_AUTH_LENGTH        20
#else   /* RIP_AUTH_LENGTH */
#	define RIP_AUTH_LENGTH        20
#endif  /* RIP_AUTH_LENGTH */
#ifdef  RIP_TRAILER_LENGTH
#	warning "Sorry! The t50 is disabling RIP_TRAILER_LENGTH!"
#	undef  RIP_TRAILER_LENGTH
#	define RIP_TRAILER_LENGTH     4
#else   /* RIP_TRAILER_LENGTH */
#	define RIP_TRAILER_LENGTH     4
#endif  /* RIP_TRAILER_LENGTH */
/* Calculating RIP Header length */
#ifdef  rip_hdr_len
#	warning "Sorry! The t50 is disabling rip_hdr_len!"
#	undef  rip_hdr_len
#	define rip_hdr_len(foo) \
			(RIP_HEADER_LENGTH + \
			RIP_MESSAGE_LENGTH + \
			(foo ? \
				RIP_AUTH_LENGTH + \
				RIP_TRAILER_LENGTH + \
				AUTH_TLEN_HMACMD5 : \
			0))
#else   /* rip_hdr_len */
#	define rip_hdr_len(foo) \
			(RIP_HEADER_LENGTH + \
			RIP_MESSAGE_LENGTH + \
			(foo ? \
				RIP_AUTH_LENGTH + \
				RIP_TRAILER_LENGTH + \
				AUTH_TLEN_HMACMD5 : \
			0))
#endif  /* rip_hdr_len */


__END_DECLS


#ifdef __cplusplus
}
#endif


#endif  /* __RIP_H */
