/* 
 * $Id: t50.c,v 2.45.3.22 2010-11-27 14:48:12-02 nbrito Exp $
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
#ifndef T50_C__
#define T50_C__ 1

#include <common.h>


/* Local prototypes. */
static void ctrlc(int32_t);
#ifdef  __HAVE_EXPIRATION__
static void piracy(int8_t *);
#endif  /* __HAVE EXPIRATION__ */


/* Local Global Variables. */
static pid_t pid = 0;
/* I do hate 'asctime()' and 'ctime()'. */
static time_t lt; static struct tm * tm = NULL;
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 2.45.3.22 $";
#endif  /* __HAVE_DEBUG__ */
/* Network socket file descriptor. */
static socket_t fd;


/* Function Name: T50 launching.

   Description:   This function launches all T50 modules.

   Targets:       N/A */
int32_t main(int32_t argc, int8_t ** argv){
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
	/* This is the same thing I use with ENG++ C code. 
	   PS: I saw something similiar in another tool. */
	static struct launch_t50_modules{
		int32_t proto;
		void (* raw)(socket_t, struct config_options);
	} t50 [] = {
		{ IPPROTO_ICMP, (void *) icmp },
		{ IPPROTO_IGMP, (void *) igmp },
		{ IPPROTO_TCP,  (void *) tcp  },
		{ IPPROTO_UDP,  (void *) udp  },
	};

	/* Getting the local time. */
	lt = time(NULL); tm = localtime(&lt);

#ifdef  __HAVE_EXPIRATION__
	/* Checking expired copy. */
	piracy(argv[0]);
#endif  /* __HAVE EXPIRATION__ */

#ifdef  __HAVE_T50__
	/* Calculating how many modules to use. */
	modules = (sizeof(t50)/sizeof(struct launch_t50_modules));
#endif  /* __HAVE_T50__ */

	/* Configuring command line interface options. */
	o = config(argc, argv);

	/* Validating command line interface options. */
	if(check(o, program) == 0)
		exit(EXIT_FAILURE);

	/* Printing a little banner. */
	fprintf(stdout, "%s version %s.%s-%s %s built on %s %s.\n", program, MAJOR_VERSION, MINOR_VERSION, BUILD_VERSION, BUILD_PLATFORM, __DATE__, __TIME__);
	fprintf(stdout, "%s experimental tool is licensed by: %s@%s.\n", program, REGISTERED_USER, REGISTERED_FQDN);
#ifdef  __HAVE_EXPIRATION__
	if((days = (EXPIRATION_LAST_DAY - tm->tm_mday)) <= 10)
		fprintf(stdout, "%s license will expire in %2d day%s (%s %2d %d 23:59:59).\n", program, days, (days == 1 ? "" : "s"), months[EXPIRATION_MONTH - 1], EXPIRATION_LAST_DAY, EXPIRATION_YEAR);
#endif  /* __HAVE EXPIRATION__ */
	fflush(stdout);

	/* Ignoring signals. */
	signal(SIGHUP,  SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	/* Hadling signals. */
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

#ifdef  __HAVE_T50__
	/* Sanitizing the threshold. */
	if(o.ip.protocol == IPPROTO_T50)
		o.threshold -= (o.threshold % modules);
#endif  /* __HAVE_T50__ */

	/* Setting socket file descriptor. */
	fd = sock();

	/* Starting time couting. */
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
	}
#endif  /* __HAVE_TURBO__ */

	if(pid == 0){
		/* Successfully launched. */
		fprintf(stdout, "%s successfully launched on %s %2d ", program, months[tm->tm_mon], tm->tm_mday);
		fprintf(stdout, "%d %.02d:%.02d:%.02d.\n", (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
		fflush(stdout);
	}

	/* Execute if flood or while threshold greater than 0. */
	while(o.flood || o.threshold--){
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
			o.threshold -= (modules-1);
			/* Reseting protocol. */
			o.ip.protocol = IPPROTO_T50;
		}
#endif  /* __HAVE_T50__ */
	}

	/* Closing the socket. */
	close(fd);

	/* Getting the local time. */
	lt = time(NULL); tm = localtime(&lt);
	/* Successfully finished. */
	fprintf(stdout, "%s successfully finished on %s %2d ", program, months[tm->tm_mon], tm->tm_mday);
	fprintf(stdout, "%d %.02d:%.02d:%.02d.\n", (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
	fflush(stdout);

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
	if((expired_first_day || expired_last_day) || expired_month || expired_year){
		/* Warning: T50 license did not start yet. */
		if(expired_first_day || ((tm->tm_mon + 1) < EXPIRATION_MONTH))
			fprintf(stderr, "%s license will start on %s %2d %d.\n", program, months[EXPIRATION_MONTH - 1], EXPIRATION_FIRST_DAY, EXPIRATION_YEAR);
		/* Warning: T50 license has expired already. */
		else if(expired_last_day || expired_month || expired_year)
			fprintf(stderr, "%s license has expired on %s %2d %d.\n", program, months[EXPIRATION_MONTH - 1], EXPIRATION_LAST_DAY, EXPIRATION_YEAR);
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
		fprintf(stderr, "signal == SIGSEGV: Buffer Overlow detected\n");
		fflush(stderr);
		exit(EXIT_FAILURE);
	}

	/* Holding SIGTRAP. */
	if(signal == SIGTRAP){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr, "signal == SIGTRAP: Lammer debugging detected\n");
		fflush(stderr);
		exit(EXIT_FAILURE);
	}

	/* Getting the local time. */
	lt = time(NULL); tm = localtime(&lt);
	if(pid == 0){
		/* Successfully finished. */
		fprintf(stdout, "\b\r%s successfully finished on %s %2d ", program, months[tm->tm_mon], tm->tm_mday);
		fprintf(stdout, "%d %.02d:%.02d:%.02d.\n", (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
		fflush(stdout);
	}

	/* Closing the socket. */
	close(fd);

	/* Exiting. */
	exit(EXIT_SUCCESS);
}
#endif  /* T50_C__ */
