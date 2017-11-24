/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the NNG Private Tool by Nelson Brito.

   This program is free software; you can redistribute it and/or modify it under
   the terms of the GNU General Public License  version 2, 1991  as published by
   the Free Software Foundation.

   This program is distributed  in the hope that it will be useful,  but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
   FOR A PARTICULAR PURPOSE.  
   
   See the GNU General Public License for more details.

   A copy of the GNU General Public License can be found at:
   http://www.gnu.org/licenses/gpl.html
   or you can write to:
   Free Software Foundation, Inc.
   59 Temple Place - Suite 330
   Boston, MA  02111-1307
   USA. */
#ifndef NNG_C__
#define NNG_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: nng.c,v 1.1 2008-09-13 13:42:46-03 nbrito Exp $ */
#include "nng.h"
#include "options.h"

/* This is main function which calls other routines. */
int main(int argc, char **argv){
	register int32_t sock;  /* socket                        */
#ifdef  __HAVE_LYRICS__
	register int32_t tmprnd;/* temporary random variable     */
#endif  /* __HAVE_LYRICS__ */
	u_int32_t count = 0,    /* counter                       */
		  on = 1;       /* status                        */
	struct payload payload; /* structure to hold the payload */
	struct options options; /* structure to hold the options */

	/* Getting CLI options. */
	options = process_options(argc, argv);

	/* Setting RAW socket. */
	if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	/* Setting IP_HDRINCL. */
	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (int8_t *)&on, sizeof(on)) < 0){
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}

	/* Warning FLOOD mode and holding signals. */
	if(options.flood){
		printf("hit Ctrl+C (^C) to stop\n\n");
		signal(SIGHUP,  SIG_IGN);
		signal(SIGKILL, ctrlc);
		signal(SIGINT,  ctrlc);
		signal(SIGTERM, ctrlc);
		signal(SIGQUIT, ctrlc);
		signal(SIGABRT, ctrlc);
		signal(SIGSTOP, ctrlc);
		signal(SIGSEGV, ctrlc);
	}

	/* Starting time couting. */
	gettimeofday(&statistic.start, (struct timezone *)0);

	/* Execute if flood or while number. */
	while(options.flood || options.threshold--){
		/* Processing payload structure. */
		payload = process_payload(options.payload, count++, options.procopt);

		/* Sending packets. */
		if((sendraw(sock, options, payload)) == -1){
			perror("sendto()");
			close(sock);
			exit(EXIT_FAILURE);
		}

		/* Setting delay. */
		if(options.delay)
			usleep(options.delay * 1000);

		/* Counting bytes sent. */
		statistic.packets++;
	}

	/* Closing the socket. */
	close(sock);

#ifdef __HAVE_LYRICS__

	/* Just for fun. ;-) */
	tmprnd = 1 + (int32_t) (2.0 * rand() / (RAND_MAX - 1.0));
	tmprnd--;

	nb(lyrics[tmprnd], 31337);

#else  /* __HAVE_LYRICS__ */

	nb(banner, 31337);
	nb(done, 31337);

#endif /* __HAVE_LYRICS__ */

	return(EXIT_SUCCESS);
}
#endif  /* NNG_C__ */
