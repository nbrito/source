/* 
 * $Id: tcp_options.h,v 5.6 2011-03-10 09:35:29-03 nbrito Exp $
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
#ifndef __TCP_OPTIONS_H
#define __TCP_OPTIONS_H 1


/* GLOBAL HEADERS/INCLUDES

   Global headers/includes used by code.
   Any new global headers/includes should be added in this section. */
#include <common.h>


#ifdef __cplusplus
extern "C" {
#endif


__BEGIN_DECLS


/* GLOBAL TCP OPTIONS DEFINITIONS

   Global TCP options definitions used by code.
   Any new global TCP options definition should be added in this section. */
/* TCP Options */
enum tcp_option{
	TCPOPT_EOL                  = 0,
#define TCPOPT_EOL                    TCPOPT_EOL
	TCPOPT_NOP,
#define TCPOPT_NOP                    TCPOPT_NOP
	TCPOPT_MSS,
#define TCPOPT_MSS                    TCPOPT_MSS
#ifdef  TCPOLEN_MSS
#	warning "Sorry! The t50 is disabling TCPOLEN_MSS!"
#	undef  TCPOLEN_MSS
#	define TCPOLEN_MSS            4
#else   /* TCPOLEN_MSS */
#	define TCPOLEN_MSS            4
#endif  /* TCPOLEN_MSS */
	TCPOPT_WSOPT,
#define TCPOPT_WSOPT                  TCPOPT_WSOPT
#ifdef  TCPOLEN_WSOPT
#	warning "Sorry! The t50 is disabling TCPOLEN_WSOPT!"
#	undef  TCPOLEN_WSOPT
#	define TCPOLEN_WSOPT          3
#else   /* TCPOLEN_WSOPT */
#	define TCPOLEN_WSOPT          3
#endif  /* TCPOLEN_WSOPT */
	TCPOPT_SACK_OK,
#define TCPOPT_SACK_OK                TCPOPT_SACK_OK
#ifdef  TCPOLEN_SACK_OK
#	warning "Sorry! The t50 is disabling TCPOLEN_SACK_OK!"
#	undef  TCPOLEN_SACK_OK
#	define TCPOLEN_SACK_OK        2
#else   /* TCPOLEN_SACK_OK */
#	define TCPOLEN_SACK_OK        2
#endif  /* TCPOLEN_SACK_OK */
	TCPOPT_SACK_EDGE,
#define TCPOPT_SACK_EDGE              TCPOPT_SACK_EDGE
/*
 * TCP Selective Acknowledgement Options (SACK) (RFC 2018)
 *
 * A SACK option that specifies n blocks will  have a length of 8*n+2
 * bytes,  so  the  40 bytes  available for TCP options can specify a
 * maximum of 4 blocks.   It is expected that SACK will often be used 
 * in conjunction with the Timestamp option used for RTTM,which takes
 * an additional 10 bytes (plus two bytes of padding); thus a maximum
 * of 3 SACK blocks will be allowed in this case.
 */
#ifdef  TCPOLEN_SACK_EDGE
#	warning "Sorry! The t50 is disabling TCPOLEN_SACK_EDGE!"
#	undef  TCPOLEN_SACK_EDGE
#	define TCPOLEN_SACK_EDGE(foo) \
			((foo * (sizeof(u_int32_t) * 2)) + \
			TCPOLEN_SACK_OK)
#else   /* TCPOLEN_SACK_EDGE */
#	define TCPOLEN_SACK_EDGE(foo) \
			((foo * (sizeof(u_int32_t) * 2)) + \
			TCPOLEN_SACK_OK)
#endif  /* TCPOLEN_SACK_EDGE */
	TCPOPT_TSOPT                = 8,
#define TCPOPT_TSOPT                  TCPOPT_TSOPT
#ifdef  TCPOLEN_TSOPT
#	warning "Sorry! The t50 is disabling TCPOLEN_TSOPT!"
#	undef  TCPOLEN_TSOPT
#	define TCPOLEN_TSOPT          10
#else   /* TCPOLEN_TSOPT */
#	define TCPOLEN_TSOPT          10
#endif  /* TCPOLEN_TSOPT */
	TCPOPT_CC                   = 11,
#define TCPOPT_CC                     TCPOPT_CC
	TCPOPT_CC_NEW,
#define TCPOPT_CC_NEW                 TCPOPT_CC_NEW
	TCPOPT_CC_ECHO,
#define TCPOPT_CC_ECHO                TCPOPT_CC_ECHO
#ifdef  TCPOLEN_CC
#	warning "Sorry! The t50 is disabling TCPOLEN_CC!"
#	undef  TCPOLEN_CC
#	define TCPOLEN_CC             6
#else   /* TCPOLEN_CC */
#	define TCPOLEN_CC             6
#endif  /* TCPOLEN_CC */
	TCPOPT_MD5                  = 19,
#define TCPOPT_MD5                    TCPOPT_MD5
#ifdef  TCPOLEN_MD5
#	warning "Sorry! The t50 is disabling TCPOLEN_MD5!"
#	undef  TCPOLEN_MD5
#	define TCPOLEN_MD5            18
#else   /* TCPOLEN_MD5 */
#	define TCPOLEN_MD5            18
#endif  /* TCPOLEN_MD5 */
	TCPOPT_AO                   = 29,
#define TCPOPT_AO                     TCPOPT_AO
#ifdef  TCPOLEN_AO
#	warning "Sorry! The t50 is disabling TCPOLEN_AO!"
#	undef  TCPOLEN_AO
#	define TCPOLEN_AO             20
#else   /* TCPOLEN_AO */
#	define TCPOLEN_AO             20
#endif  /* TCPOLEN_AO */
/*
 * Transmission Control Protocol (TCP) (RFC 793)
 *
 * Padding:  variable
 *
 *  The TCP header padding is used to ensure that the TCP header ends
 *  and data begins on a 32 bit boundary.  The padding is composed of
 *  zeros.
 */
#ifdef  TCPOLEN_PADDING
#	warning "Sorry! The t50 is disabling TCPOLEN_PADDING!"
#	undef  TCPOLEN_PADDING
#	define TCPOLEN_PADDING(foo) \
			((foo & 3) ? \
				sizeof(u_int32_t) - (foo & 3) : \
			0)
#else   /* TCPOLEN_PADDING */
#	define TCPOLEN_PADDING(foo) \
			((foo & 3) ? \
				sizeof(u_int32_t) - (foo & 3) : \
			0)
#endif  /* TCPOLEN_PADDING */
};
/* TCP Options bitmask. */
enum tcp_option_bitmask{
	TCP_OPTION_MSS              = 0x01,
#define TCP_OPTION_MSS                TCP_OPTION_MSS
	TCP_OPTION_WSOPT            = 0x02,
#define TCP_OPTION_WSOPT              TCP_OPTION_WSOPT
	TCP_OPTION_TSOPT            = 0x04,
#define TCP_OPTION_TSOPT              TCP_OPTION_TSOPT
	TCP_OPTION_SACK_OK          = 0x08,
#define TCP_OPTION_SACK_OK            TCP_OPTION_SACK_OK
	TCP_OPTION_CC               = 0x10,
#define TCP_OPTION_CC                 TCP_OPTION_CC
	TCP_OPTION_CC_NEXT          = 0x20,
#define TCP_OPTION_CC_NEXT            TCP_OPTION_CC_NEXT
	TCP_OPTION_SACK_EDGE        = 0x40,
#define TCP_OPTION_SACK_EDGE          TCP_OPTION_SACK_EDGE
};


/* Function Name: TCP options size calculation.

   Description:   This function calculates the size of TCP options.

   Targets:       N/A */
__inline__ static size_t tcp_options_len(const u_int8_t foo, const u_int8_t bar, const u_int8_t baz){
	static size_t size;

	/*
	 * The code starts with size '0' and it accumulates all the required
	 * size if the conditionals match. Otherwise, it returns size '0'.
	 */
	size = 0;

	/*
	 * TCP Options has Maximum Segment Size (MSS) Option defined.
	 */
	if((foo & TCP_OPTION_MSS) == TCP_OPTION_MSS)
		size += TCPOLEN_MSS;

	/*
	 * TCP Options has Window Scale (WSopt) Option defined.
	 */
	if((foo & TCP_OPTION_WSOPT) == TCP_OPTION_WSOPT)
		size += TCPOLEN_WSOPT;

	/*
	 * TCP Options has Timestamp (TSopt) Option defined.
	 */
	if((foo & TCP_OPTION_TSOPT) == TCP_OPTION_TSOPT)
		size += TCPOLEN_TSOPT;

	/*
	 * TCP Options has Selective Acknowledgement (SACK-Permitted) Option
	 * defined.
	 */
	if((foo & TCP_OPTION_SACK_OK) == TCP_OPTION_SACK_OK)
		size += TCPOLEN_SACK_OK;

	/*
	 * TCP Options has Connection Count (CC) Option defined.
	 */
	if((foo & TCP_OPTION_CC) == TCP_OPTION_CC)
		size += TCPOLEN_CC;

	/*
	 * TCP Options has CC.NEW or CC.ECHO Option defined.
	 */
	if((foo & TCP_OPTION_CC_NEXT) == TCP_OPTION_CC_NEXT)
		size += TCPOLEN_CC;

	/*
	 * TCP Options has Selective Acknowledgement (SACK) Option defined.
	 */
	if((foo & TCP_OPTION_SACK_EDGE) == TCP_OPTION_SACK_EDGE)
		size += TCPOLEN_SACK_EDGE(1);

	/*
	 * Defining it the size should use MD5 Signature Option or the brand
	 * new TCP Authentication Option (TCP-AO).
	 */
	size += bar ? TCPOLEN_MD5 : 0;
	size += baz ? TCPOLEN_AO  : 0;

	return(size);
}


__END_DECLS


#ifdef __cplusplus
}
#endif


#endif  /* __TCP_OPTIONS_H */
