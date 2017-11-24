/* 
 * $Id: resolv.c,v 1.6 2009-08-16 14:17:54-03 nbrito Exp $
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
ifndef RESOLV_C__
#define RESOLV_C__ 1

#include <common.h>

/* Function Name: Resolv routine.

   Description:   

   Targets:       N/A */
const in_addr_t resolv(const u_int8_t * host){
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
