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
#ifndef RESOLV_C__
#define RESOLV_C__ 1

/* Nelson Brito <nbrito@sekure.org>
   $Id: resolv.c,v 1.2 2008-08-23 10:10:07-03 nbrito Exp $ */
#include "common.h"

/* Name and IP address resolving routine.
   Returns the IP address to process_options. */
const in_addr_t resolv(const u_int8_t *host){
	static in_addr_t ip_addr;
	struct hostent * hostname;
	
	if((hostname = gethostbyname(host)) == NULL){
#ifdef  __HAVE_DEBUG__

		printf("function %s in file %s (line %d)\n",
				__FUNCTION__,
				__FILE__,
				(__LINE__ - 6));

#endif  /* __HAVE_DEBUG__ */
		perror("gethostbyname()");
		exit(EXIT_FAILURE);
	}

	memcpy(&ip_addr, hostname->h_addr, hostname->h_length);
	return(ip_addr);
}
#endif  /* RESOLV_C__ */
