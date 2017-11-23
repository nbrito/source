/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the ENG Private Tool by Nelson Brito.

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
#ifndef CONNECT_C__
#define CONNECT_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: connect.c,v 1.6 2008-09-12 01:43:23-03 nbrito Exp $ */
#include "common.h"

/* Connect shell routine. 
   Returns the a of connect(). */
const int32_t connect_shell(struct options options){
	fd_set     rfds;
	register   int32_t a = 0,    /* status to be returned */
			   b;        /* socket                */
	u_int8_t   buffer[2048],     /* buffer to read/write  */
		 * connected = "connected!!!\n";
	struct     sockaddr_in sin;  /* socket address        */

	/* Setting SOCKADDR structure. */
        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(options.port);
        sin.sin_addr.s_addr = options.daddr;

	if((b = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		perror("socket()");
		exit(EXIT_FAILURE);
	}
	
        if(connect(b, (struct sockaddr *)&sin, sizeof(sin)) < 0){
		perror("connect()");
		exit(EXIT_FAILURE);
	}

	nb(connected, 31337);

	/* Ripped from TESO code. */
	while(TRUE){
		FD_SET(0, &rfds);
		FD_SET(b, &rfds);

		select(b + 1, &rfds, NULL, NULL, NULL);

		if(FD_ISSET(0, &rfds)) {
			a = read(0, buffer, sizeof(buffer));

			if(a <= 0)
				return(a);
            
			write(b, buffer, a);
		}

		if(FD_ISSET(b, &rfds)){
			a = read(b, buffer, sizeof(buffer));

			if(a <= 0)
				return(a);

			write(1, buffer, a);
		}
	}

	/* Returning the a. */
	return(a);
}
#endif  /* CONNECT_C__ */
