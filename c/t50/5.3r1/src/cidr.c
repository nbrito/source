/* 
 * $Id: cidr.c,v 5.10 2011-04-12 22:31:30-03 nbrito Exp $
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
#ifndef CIDR_C__
#define CIDR_C__ 1

#include <common.h>


#ifdef  __HAVE_CIDR__
/* 
 * Local Global Variables.
 */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 5.10 $";
#endif  /* __HAVE_DEBUG__ */


/* Function Name: CIDR configuration tiny C algorithm.

   Description:   This function calculates and configure the CIDR.

   Targets:       N/A */
struct cidr config_cidr(u_int32_t bits, in_addr_t address){
	/* Network mask and 'all bits on'. */
	static u_int32_t  netmask = 0, all_bits_on = 0xffffffff;
	/* CIDR host identifier and first IP address */
	static struct cidr cidr = { 0, 0 };

	/* Configuring CIDR IP addresses. */
	if(bits){
		/*
		 * @nbrito -- Thu Dec 23 13:06:39 BRST 2010
		 * Here is a description of how to calculate,  correctly,  the number of
		 * hosts and IP addresses based on CIDR -- three instructions line.
		 *
		 * (1) Calculate the 'Network Mask' (two simple operations):
		 *  a) Bitwise shift to the right (>>) '0xffffffff' using CIDR gives the
		 *     number of bits to calculate the 'Network Mask'.
		 *  b) Bitwise logic NOT (~) to turn off the bits that are on,  and turn
		 *     on the bits that are off gives the 'Network Mask'.
		 *
		 * (2) Calculate the number of  hosts'  IP  addresses  available  to the 
		 *     current CIDR (two simple operations):
		 *  a) Subtract  CIDR from 32 gives the host identifier's (bits) portion
		 *     for the IP address.
		 *  b) Bitwise shift left (<<) '1' is the host identifier (bits), giving
		 *     the number of all IP addresses available for the CIDR .
		 *     NOTE: Subtracting two from this math skips both 'Network Address'
		 *           and 'Broadcast Address'.
		 *
		 * (3) Calculate initial host IP address (two simple operations):
		 *  a) Convert IP address to little-endian ('ntohl(3)').
		 *  b) Bitwise logic AND (&) of host identifier (bits) portion of the IP
		 *     address and 'Network Mask' adding one  gives the first IP address
		 *     for the CIDR.
		 */
		netmask         = ~(all_bits_on >> bits);
		cidr.__1st_addr = (ntohl(address) & netmask) + 1;
		/* Really good tip by Gustavo Scotti (@gustavoid). */
		cidr.hostid     = (1 << (32 - bits)) - 2;
		/*
		 * XXX Sanitizing the maximum host identifier's IP addresses.
		 * XXX Should never reaches here!!!
		 */
		if(cidr.hostid > MAXIMUM_IP_ADDRESSES){
#ifdef  __HAVE_DEBUG__
			ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
			fprintf(stderr,
				"%s(): %s has detected an internal error -- please, report\n",
				__FUNCTION__,
				program);
			fprintf(stderr,
				"cidr.hostid > MAXIMUM_IP_ADDRESSES: Probably a specific platform error\n");
			fflush(stderr);
			exit(EXIT_FAILURE);
		}
	}

	/* Returning CIDR. */
	return(cidr);
}
#endif  /* __HAVE_CIDR__ */
#endif  /* CIDR_C__ */
