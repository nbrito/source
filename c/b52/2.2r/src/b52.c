/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the B52 Private Tool by Nelson Brito.

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
#ifndef B52_C__
#define B52_C__ 1

/* Nelson Brito <nbrito@sekure.org>
   $Id: b52.c,v 1.1 2008-08-23 10:06:08-03 nbrito Exp $ */
#include "b52.h"

/* This is main function which calls other routines. */
int main(int argc, char **argv){
	register int32_t sock;  /* socket                        */
	u_int32_t on = 1;       /* status                        */
	struct options options; /* structure to hold the options */

	/* Getting CLI options. */
	options = process_options(argc, argv);

	/* Setting RAW socket. */
	if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
#ifdef  __HAVE_DEBUG__
		printf("function %s in file %s (line %d)\n",
				__FUNCTION__,
				__FILE__,
				(__LINE__ - 6));

#endif  /* __HAVE_DEBUG__ */
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	/* Setting IP_HDRINCL. */
	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (int8_t *)&on, sizeof(on)) < 0){
#ifdef  __HAVE_DEBUG__

					printf("function %s in file %s (line %d)\n",
						__FUNCTION__,
						__FILE__,
						(__LINE__ - 6));

#endif  /* __HAVE_DEBUG__ */
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
		
		/* Sending packets. */
		if((sendraw(sock, options)) == -1){
#ifdef  __HAVE_DEBUG__

					printf("function %s in file %s (line %d)\n",
						__FUNCTION__,
						__FILE__,
						(__LINE__ - 6));

#endif  /* __HAVE_DEBUG__ */
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

	nb(done, 31337);

	return(EXIT_SUCCESS);
}
#endif  /* B52_C__ */
