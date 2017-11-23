/* 
 * $Id: check.c,v 5.24 2011-03-09 18:51:15-03 nbrito Exp $
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
#ifndef CHECK_C__
#define CHECK_C__ 1

#include <common.h>


/* 
 * Local Global Variables.
 */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 5.24 $";
#endif  /* __HAVE_DEBUG__ */


/* Function Name: Command line interface options validation.

   Description:   This function validates the command line interface options.

   Targets:       N/A */
u_int32_t check(const struct config_options o, const int8_t * program){
	/* Warning missed privileges. */
	if(getuid()){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr,
			"%s(): You must have privileges to run the %s\n",
			__FUNCTION__,
			program);
		fflush(stderr);
		return(EXIT_FAILURE);
	}

	/* Warning missed target. */
	if(o.ip.daddr == INADDR_ANY){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr,
			"Type \"%s --help\" for further information.\n",
			program);
		fflush(stderr);
		return(EXIT_FAILURE);
	}

#ifdef  __HAVE_CIDR__
	/* Sanitizing the CIDR. */
	if((o.bits < CIDR_MINIMUM  ||
	    o.bits > CIDR_MAXIMUM) &&
	    o.bits != 0){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr,
			"%s(): CIDR cannot be smaller than %d or greater than %d\n",
			__FUNCTION__,
			CIDR_MINIMUM,
			CIDR_MAXIMUM);
		fflush(stderr);
		return(EXIT_FAILURE);
	}
#endif  /* __HAVE_CIDR__ */

	/* Sanitizing the TCP Options SACK_Permitted and SACK Edges. */
	if((o.tcp.options & TCP_OPTION_SACK_OK) == TCP_OPTION_SACK_OK &&
	   (o.tcp.options & TCP_OPTION_SACK_EDGE) == TCP_OPTION_SACK_EDGE){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr,
			"%s(): TCP options SACK-Permitted and SACK Edges are not allowed\n",
			__FUNCTION__);
		fflush(stderr);
		return(EXIT_FAILURE);
	}

	/* Sanitizing the TCP Options T/TCP CC and T/TCP CC.ECHO. */
	if((o.tcp.options & TCP_OPTION_CC) == TCP_OPTION_CC &&
	   (o.tcp.cc_echo)){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr,
			"%s(): TCP options T/TCP CC and T/TCP CC.ECHO are not allowed\n",
			__FUNCTION__);
		fflush(stderr);
		return(EXIT_FAILURE);
	}

#ifdef  __HAVE_LIMITATION__
	/* Testing IANA IP address allocation for private internets (RFC 1700, 1918 and 3330). */
	switch(ntohl(o.ip.daddr) & 0xff000000){
		/* Allowing 10/8 (RFC 1918). */
		case 0x0a000000:
			break;
		/* Allowing 127/8 (RFC 1700). */
		case 0x7f000000:
			break;
		/* Allowing 169.254/16 (RFC 3330). */
		case 0xa9000000:
			if((ntohl(o.ip.daddr) & 0xffff0000) != 0xa9fe0000){
#ifdef  __HAVE_DEBUG__
				ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
				fprintf(stderr,
					"%s(): Limited version is RFC 1700, RFC 1918 and RFC 3330 compliance\n",
					__FUNCTION__);
				fflush(stderr);
				return(EXIT_FAILURE);
			}
			break;
		/* Allowing 172.16/12 (RFC 1918). */
		case 0xac000000:
			if((ntohl(o.ip.daddr) & 0xffff0000) < 0xac100000 || \
			   (ntohl(o.ip.daddr) & 0xffff0000) > 0xac1f0000){
#ifdef  __HAVE_DEBUG__
				ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
				fprintf(stderr,
					"%s(): Limited version is RFC 1700, RFC 1918 and RFC 3330 compliance\n",
					__FUNCTION__);
				fflush(stderr);
				return(EXIT_FAILURE);
			}
			break;
		/* Allowing 192.168/16 (RFC 1918). */
		case 0xc0000000:
			if((ntohl(o.ip.daddr) & 0xffff0000) != 0xc0a80000){
#ifdef  __HAVE_DEBUG__
				ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
				fprintf(stderr,
					"%s(): Limited version is RFC 1700, RFC 1918 and RFC 3330 compliance\n",
					__FUNCTION__);
				fflush(stderr);
				return(EXIT_FAILURE);
			}
			break;
		/* Blocking all other IP addresses. */
		default:
#ifdef  __HAVE_DEBUG__
			ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
				fprintf(stderr,
					"%s(): Limited version is RFC 1700, RFC 1918 and RFC 3330 compliance\n",
					__FUNCTION__);
			fflush(stderr);
			return(EXIT_FAILURE);
			break;
	}
#endif  /* __HAVE_LIMITATION__ */


#ifdef  __HAVE_TURBO__
	/* Sanitizing TURBO mode. */
	if(o.turbo && o.flood == 0){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr,
			"%s(): [TURBO] mode is only available with FLOOD mode\n",
			__FUNCTION__);
		fflush(stderr);
		return(EXIT_FAILURE);
	}
#endif  /* __HAVE_TURBO__ */

#ifdef  __HAVE_T50__
	/* Sanitizing the threshold. */
	if(o.ip.protocol == IPPROTO_T50    && 
	   o.threshold < T50_THRESHOLD_MIN && 
	   o.flood == 0){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr,
			"%s(): Protocol %s cannot have threshold smaller than %d\n",
			__FUNCTION__,
			modules[o.ip.protoname],
			T50_THRESHOLD_MIN);
		fflush(stderr);
		return(EXIT_FAILURE);
	}
#endif  /* __HAVE_T50__ */

	/* Warning FLOOD mode. */
	if(o.flood){
		fprintf(stdout,
			"%s entering in FLOOD",
			program);
#ifdef  __HAVE_TURBO__
		/* Warning TURBO mode. */
		if(o.turbo)
			fprintf(stdout,
				"+[TURBO]");
#endif  /* __HAVE_TURBO__ */
#ifdef  __HAVE_CIDR__
		/* Warning CIDR mode. */
		if(o.bits)
			fprintf(stdout,
				"+{DDoS}");
#endif  /* __HAVE_CIDR__ */
		fprintf(stdout,
			" simulate mode, please, hit Ctrl+C to stop!\n\a");
		fflush(stdout);
	}

	/* Returning. */
	return(EXIT_SUCCESS);
}
#endif  /* CHECK_C__ */
