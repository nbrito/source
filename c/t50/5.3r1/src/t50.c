/* 
 * $Id: t50.c,v 3.16 2011-03-11 14:30:27-03 nbrito Exp $
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
#ifndef T50_C__
#define T50_C__ 1

#include <common.h>


/*
 * Local prototypes.
 */
static void ctrlc(int32_t);
#ifdef  __HAVE_EXPIRATION__
static void piracy(int8_t *);
#endif  /* __HAVE EXPIRATION__ */


/*
 * Local Global Variables.
 */
static pid_t pid = 0;
static time_t lt;
static struct tm * tm = NULL;
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 3.16 $";
#endif  /* __HAVE_DEBUG__ */
static socket_t fd;


/* Function Name: T50 launching.

   Description:   This function launches all T50 modules.

   Targets:       N/A */
int32_t __t50(int32_t argc, int8_t ** argv){
	/* Command line interface options. */
	static struct config_options o;
	/* Seed to use with 'srand()'. */
	static struct timeval seed;
#ifdef  __HAVE_T50__
	/* Modules counter. */
	static u_int32_t module = 0;
	/* Total number of modules. */
	static u_int32_t modules = 0;
#endif  /* __HAVE_T50__ */
#ifdef  __HAVE_EXPIRATION__
	/* Remaining days to expire. */
	static u_int32_t days = 0;
#endif  /* __HAVE_EXPIRATION__ */
#ifdef  __HAVE_CIDR__
	/* Possible CIDR IP addresses table. */
	static in_addr_t addresses[MAXIMUM_IP_ADDRESSES];
	/* Counter and random destination address. */
	static u_int32_t counter = 0, rand_daddr = 0;
	/* CIDR host identifier and first IP address. */
	static struct cidr cidr = { 0, 0 };
#endif  /* __HAVE_CIDR__ */
	/* This is the same thing I use with ENG++ C code. */
	static struct launch_t50_modules{
		int32_t proto;
		const void *(* raw)(const socket_t, const struct config_options);
	} t50 [] = {
		{ IPPROTO_ICMP,  icmp   },
		{ IPPROTO_IGMP,  igmpv1 },
		{ IPPROTO_IGMP,  igmpv3 },
		{ IPPROTO_TCP,   tcp    },
		{ IPPROTO_EGP,   egp    },
		{ IPPROTO_UDP,   udp    },
		{ IPPROTO_UDP,   ripv1  },
		{ IPPROTO_UDP,   ripv2  },
		{ IPPROTO_DCCP,  dccp   },
		{ IPPROTO_RSVP,  rsvp   },
		{ IPPROTO_AH,    ipsec  },
		{ IPPROTO_EIGRP, eigrp  },
		{ IPPROTO_OSPF,  ospf   },
	};

	/* Getting the local time. */
	lt = time(NULL); tm = localtime(&lt);

#ifdef  __HAVE_EXPIRATION__
	/* First important thing is: checking expired copy. */
	piracy(argv[0]);
#endif  /* __HAVE EXPIRATION__ */

	/* Second important things is: ignoring signals. */
	signal(SIGHUP,  SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	/* Third important thing is: handling signals. */
	signal(SIGINT,  ctrlc);
	signal(SIGILL,  ctrlc);
	signal(SIGQUIT, ctrlc);
	signal(SIGABRT, ctrlc);
	signal(SIGTRAP, ctrlc);
	signal(SIGKILL, ctrlc);
	signal(SIGTERM, ctrlc);
	signal(SIGSTOP, ctrlc);
	signal(SIGTSTP, ctrlc);
	signal(SIGSEGV, ctrlc);
#ifdef  __HAVE_TURBO__
	signal(SIGCHLD, ctrlc);
#endif  /* __HAVE_TURBO__ */

	/* Configuring command line interface options. */
	o = config(argc, argv);

	/* Validating command line interface options. */
	if(check(o, program) == EXIT_FAILURE)
		exit(EXIT_FAILURE);

	/* Printing a little banner. */
	fprintf(stdout,
		"%s version %s.%s.%s-%s %s built on %s %s.\n",
		program,
		MAJOR_VERSION,
		MINOR_VERSION,
		T50_REVISION,
		BUILD_VERSION,
		BUILD_PLATFORM,
		__DATE__,
		__TIME__);
	fprintf(stdout,
		"%s experimental tool is licensed by: %s@%s.\n",
		program,
		REGISTERED_USER,
		REGISTERED_FQDN);
#ifdef  __HAVE_EXPIRATION__
	if((EXPIRATION_LAST_DAY - tm->tm_mday) == 0)
		fprintf(stdout,
			"%s license will expire in %.02d:%.02d:%.02d (%s %2d %d 23:59:59).\n",
			program,
			(EXPIRATION_LAST_HOUR - tm->tm_hour),
			(EXPIRATION_LAST_MINUTE - tm->tm_min),
			(EXPIRATION_LAST_SECOND - tm->tm_sec),
			months[EXPIRATION_MONTH - 1],
			EXPIRATION_LAST_DAY,
			EXPIRATION_YEAR);
	else if((days = (EXPIRATION_LAST_DAY - tm->tm_mday)) <= 10)
		fprintf(stdout,
			"%s license will expire in %2d day%s (%s %2d %d 23:59:59).\n",
			program,
			days,
			(days == 1 ? "" : "s"),
			months[EXPIRATION_MONTH - 1],
			EXPIRATION_LAST_DAY,
			EXPIRATION_YEAR);

#endif  /* __HAVE EXPIRATION__ */
	fflush(stdout);

#ifdef  __HAVE_T50__
	/* Calculating how many modules to use. */
	modules = (sizeof(t50)/sizeof(struct launch_t50_modules));

	/* Sanitizing the threshold. */
	if(o.ip.protocol == IPPROTO_T50)
		o.threshold -= (o.threshold % modules);
#endif  /* __HAVE_T50__ */

	/* Setting socket file descriptor. */
	fd = sock();

	/* Starting time counting. */
	gettimeofday(&seed, (struct timezone *)0);

	/* Using microseconds as seed. */
	srand((unsigned) seed.tv_usec);

#ifdef  __HAVE_TURBO__
	/* Entering in TURBO. */
	if(o.turbo){
		/* Creating child process. */
		if((pid = fork()) == -1){
#ifdef  __HAVE_DEBUG__
			ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
			perror("fork()");
			exit(EXIT_FAILURE);
		}

		/* Duplicating socket file descriptor. Not sure if it is necessary. */
		if(dup(fd) == -1){
#ifdef  __HAVE_DEBUG__
			ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
			perror("dup()");
			exit(EXIT_FAILURE);
		}

		/* Setting the priority to lowest (?) one. */
		if(setpriority(PRIO_PROCESS, PRIO_PROCESS, -15)  == -1){
#ifdef  __HAVE_DEBUG__
			ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
			perror("setpriority()");
			exit(EXIT_FAILURE);
		}
	}
#endif  /* __HAVE_TURBO__ */

#ifdef  __HAVE_CIDR__
	/* Calculating CIDR for destination address. */
	cidr = config_cidr(o.bits, o.ip.daddr);
	/* Computing all the hosts' IP addresses. */
	if(cidr.hostid){
		/* Storing all the IP address available to the current CIDR. */
		while(counter < cidr.hostid){
			addresses[counter] = htonl(cidr.__1st_addr++);
			counter++;
		}
	}
#endif  /* __HAVE_CIDR__ */

	/* Getting the local time. */
	lt = time(NULL); tm = localtime(&lt);
	/* Printing just once. */
	if(pid == 0){
		/* Successfully launched. */
		fprintf(stdout,
			"%s successfully launched on %s %2d %d %.02d:%.02d:%.02d.\n",
			program,
			months[tm->tm_mon],
			tm->tm_mday,
			(tm->tm_year + 1900),
			tm->tm_hour, tm->tm_min,
			tm->tm_sec);
		fflush(stdout);
	}

	/* Execute if flood or while threshold greater than 0. */
	while(o.flood || o.threshold--){
#ifdef  __HAVE_CIDR__
		/* Setting the destination IP address to RANDOM IP address. */
		if(cidr.hostid){
			/* Generation RANDOM position for computed IP addresses. */
			rand_daddr = (u_int32_t) ((float)(cidr.hostid) * rand() / (RAND_MAX + 1.0));
			/* Using RANDOM destination IP address. */
			o.ip.daddr = addresses[rand_daddr];
		}
#endif  /* __HAVE_CIDR__ */

#ifdef  __HAVE_T50__
		/* Sending ICMP/IGMP/TCP/UDP packets. */
		if(o.ip.protocol != IPPROTO_T50){
#endif  /* __HAVE_T50__ */
			/* Getting the correct protocol. */
			o.ip.protocol = t50[o.ip.protoname].proto;
			/* Launching t50 module. */
			t50[o.ip.protoname].raw(fd, o);
#ifdef  __HAVE_T50__
		}
		/* Sending T50 packets. */ 
		 else {
			for(module = 0 ; module < modules ; module++){
				/* Getting the correct protocol. */
				o.ip.protocol = t50[module].proto;
				/* Launching t50 module. */
				t50[module].raw(fd, o);
			}
			/* Sanitizing the threshold. */
			o.threshold -= modules - 1;
			/* Reseting protocol. */
			o.ip.protocol = IPPROTO_T50;
		}
#endif  /* __HAVE_T50__ */
	}

	/* Closing the socket. */
	close(fd);

	/* Getting the local time. */
	lt = time(NULL); tm = localtime(&lt);
	/* Printing just once. */
	if(pid == 0){
		/* Successfully finished. */
		fprintf(stdout,
			"%s successfully finished on %s %2d %d %.02d:%.02d:%.02d.\n",
			program,
			months[tm->tm_mon],
			tm->tm_mday,
			(tm->tm_year + 1900),
			tm->tm_hour,
			tm->tm_min,
			tm->tm_sec);
		fflush(stdout);
	}

	/* Returning. */
	return(EXIT_SUCCESS);
}


#ifdef  __HAVE_EXPIRATION__
/* Function Name: Expired version checking (30 days is the maximum allowed).

   Description:   This function checks for expired version (piracy).

   Targets:       N/A */
static void piracy(int8_t * illegal){
	static u_int32_t expired_first_day = 0, expired_last_day = 0, expired_month = 0, expired_year = 0;

	/* Checking expiration DAY. */
	if(tm->tm_mday < EXPIRATION_FIRST_DAY)
		expired_first_day++;
	if(tm->tm_mday > EXPIRATION_LAST_DAY)
		expired_last_day++;

	/* Checking expiration MONTH. */
	if((tm->tm_mon + 1) != EXPIRATION_MONTH)
		expired_month++;

	/* Checking expiration YEAR. */
	if((tm->tm_year + 1900) !=  EXPIRATION_YEAR)
		expired_year++;

	/* Has T50 expired? */
	if((expired_first_day || 
	    expired_last_day) || 
	    expired_month     || 
	    expired_year){
		/* Warning: T50 license did not start yet. */
		if(expired_first_day                  ||
		  (tm->tm_mon + 1) < EXPIRATION_MONTH ||
		  ((tm->tm_year + 1900) < EXPIRATION_YEAR))
			fprintf(stderr,
				"%s license will start on %s %2d %d.\n",
				program,
				months[EXPIRATION_MONTH - 1],
				EXPIRATION_FIRST_DAY,
				EXPIRATION_YEAR);
		/* Warning: T50 license has expired already. */
		else if(expired_last_day ||
		        expired_month    ||
		        expired_year)
			fprintf(stderr,
				"%s license has expired on %s %2d %d.\n",
				program,
				months[EXPIRATION_MONTH - 1],
				EXPIRATION_LAST_DAY,
				EXPIRATION_YEAR);
		fflush(stderr);
		/* Unlinking the unlicensed version of T50. */
		unlink(illegal);
		exit(EXIT_SUCCESS);
	}
}
#endif  /* __HAVE_EXPIRATION__ */


/* Function Name: Control-C handling.

   Description:   This function handles Control-C (^C) keys.

   Targets:       N/A */
static void ctrlc(int32_t signal){
	/* Holding SIGSEGV. */
	if(signal == SIGSEGV){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr,
			"%s(): %s has detected an internal error -- please, report\n",
			__FUNCTION__,
			program);
		fprintf(stderr,
			"signal == SIGSEGV: Buffer Overflow detected\n");
		fflush(stderr);
		exit(EXIT_FAILURE);
	}

	/* Holding SIGTRAP. */
	if(signal == SIGTRAP){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr,
			"%s(): %s has detected an internal error -- please, report\n",
			__FUNCTION__,
			program);
		fprintf(stderr,
			"signal == SIGTRAP: Lammer debugging detected\n");
		fflush(stderr);
		exit(EXIT_FAILURE);
	}

	/* Getting the local time. */
	lt = time(NULL); tm = localtime(&lt);
	/* Printing just once. */
	if(pid == 0){
		/* Successfully finished. */
		fprintf(stdout,
			"\b\r%s successfully finished on %s %2d %d %.02d:%.02d:%.02d.\n",
			program,
			months[tm->tm_mon],
			tm->tm_mday,
			(tm->tm_year + 1900),
			tm->tm_hour,
			tm->tm_min,
			tm->tm_sec);
		fflush(stdout);
	}

	/* Closing the socket. */
	close(fd);

	/* Exiting. */
	exit(EXIT_SUCCESS);
}
#endif  /* T50_C__ */
