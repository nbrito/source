/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the F117 Private Tool by Nelson Brito.

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
#ifndef __F117_H
#define __F117_H 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: f117.h,v 1.1 2008-09-12 15:36:14-03 nbrito Exp $ */
#include <signal.h>
#include "common.h"

__BEGIN_DECLS

#ifdef  F117_C__
/* XXX - Internal declarations. */

int8_t * done    = "is the old-school back??? ;)\n";

/* Statistics metrics. */
struct statistic{
	float   seconds;       /* execution time in seconds */
	int32_t packets;       /* amount of packets         */
	struct  timeval start; /* start time (sec & usec)   */
	struct  timeval stop;  /* stop time (sec & usec)    */
};

/* Statistics metrics. */
struct statistic statistic = {
	0,      /* execution time in seconds */
	0,      /* amount of packets         */
	{0, 0}, /* time start (sec & usec)   */
	{0, 0}  /* time stop (sec & usec)    */
};

/* Ctrl+C key routine. */
inline void ctrlc(int32_t s){
	/* Holding SIGSEGV. */
	if(s == SIGSEGV){
		printf("fix me\n");
		exit(EXIT_FAILURE);
	}

	/* Stoping time couting. */
        gettimeofday(&statistic.stop, (struct timezone *)0);

	/* Computing execution time. */
        statistic.seconds = (statistic.stop.tv_sec - statistic.start.tv_sec)\
		+ (statistic.stop.tv_usec - statistic.start.tv_usec)/1000000.0;

        /* Printing statistics. */ 
        printf("injected %i packets in %.2f sec (rating @ %.2f pps)\n\n",\
		statistic.packets, statistic.seconds,\
		(statistic.packets / statistic.seconds));

	/* Exiting. */
	exit(EXIT_SUCCESS);
}

#else   /* F117_C__ */
/* XXX - External declarations. */

#endif  /* F117_C__ */

__END_DECLS

#endif  /* __F117_H */
