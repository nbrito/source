/* 
 * $Id: in_cksum.c,v 1.5 2009-08-15 14:05:21-03 nbrito Exp $
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
#ifndef IN_CKSUM_C__
#define IN_CKSUM_C__ 1

#include <common.h> 

/* Function Name: Checksum routine.

   Description:   This is creates the packets checksum.

   Targets:       N/A */
const u_int16_t in_cksum(register u_int16_t *data, register int32_t length){
	register int32_t nleft = length;
	register u_int16_t * w = data;
	register int32_t sum = 0;
	u_int16_t answer = 0;

	/* Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits. */
	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if(nleft == 1){
		*(u_int8_t *) (&answer) = *(u_int8_t *) w;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum  = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16);                 /* add carry */

	answer = ~sum;                      /* truncate to 16 bits */
	return(answer);
}
#endif  /* IN_CKSUM_C__ */
