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
#ifndef JMPADDR_C__
#define JMPADDR_C__ 1
/* Nelson Brito <nbrito@sekure.org>
 *    $Id: jmpaddr.c,v 1.6 2008-09-12 13:23:20-03 nbrito Exp $ */
#include "common.h"

u_int64_t jmp[15] =   /* some possibles jmp short/near */
		{
			0x59eb59eb59eb59ebLL, 0x58eb58eb58eb58ebLL, 0x57eb57eb57eb57ebLL, 
			0x56eb56eb56eb56ebLL, 0x55eb55eb55eb55ebLL, 0x54eb54eb54eb54ebLL, 
			0x53eb53eb53eb53ebLL, 0x52eb52eb52eb52ebLL, 0x51eb51eb51eb51ebLL, 
			0x50eb50eb50eb50ebLL, 0x4feb4feb4feb4febLL, 0x4eeb4eeb4eeb4eebLL, 
			0x4deb4deb4deb4debLL, 0x4ceb4ceb4ceb4cebLL, 0x4beb4beb4beb4bebLL, 
		};

/* Jump Address processing routine.
   Returns the a random jump short/near address be sent by sendexp(). */
u_int64_t process_jmpaddr(register u_int64_t address){
	int32_t   c = 0;         /* simple counter                */
        struct    timeval seed;  /* seed for random               */

	/* Using microseconds as seed. */
	gettimeofday(&seed, (struct timezone *)0);
	srand((unsigned) seed.tv_usec);

	/* Getting a random jmp short/near address. */
	c = sizeof(jmp)/sizeof(u_int64_t);
	c =(int)((float)c * rand() / (RAND_MAX + 1.0));
	address = jmp[c];
	
	return(address);
}
#endif  /* JMPADDR_C__ */
