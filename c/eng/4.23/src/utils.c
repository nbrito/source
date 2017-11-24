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
#ifndef UTILS__C_
#define UTILS__C_ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: utils.c,v 1.8 2008-09-14 17:57:14-03 nbrito Exp $ */
#include "common.h" 

/* Packet's check summing routine.
   Returns the checksum to sendexp().  */
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

/* Name and IP address resolving routine.
   Returns the IP address to process_options. */
const in_addr_t resolv(const u_int8_t *host){
	static in_addr_t ip_addr;
	struct hostent * hostname;
	
	if((hostname = gethostbyname(host)) == NULL){
		perror("gethostbyname()");
		exit(EXIT_FAILURE);
	}

	memcpy(&ip_addr, hostname->h_addr, hostname->h_length);
	return(ip_addr);
}

/* Random strings processing routine.
   Returns the random strings to be sent by sendexp(). */
const u_int8_t * process_string(u_int8_t * buffer, register u_int32_t length){
	u_int32_t i = 0;           /* counter           */
	register u_int32_t choice; /* random choice     */
	struct  timeval  seed;     /* seed for random   */

	/* Using microseconds as seed. */
	gettimeofday(&seed, (struct timezone *)0);
	srand((unsigned) seed.tv_usec);
	
	buffer = (u_int8_t *) malloc(length);

	choice = 1 + (u_int32_t) (2.0 * rand() / (RAND_MAX + 1.0));

	switch(choice){
		case 1: /* using uppercase alphabet letters */
			for(i = 0 ; i < length ; i++)
				buffer[i] = 65 + (u_int32_t) (26.0 * rand() / (RAND_MAX + 1.0));
			break;
		case 2: /* using mixed uppercase and lowercase alphabet letters */
			for(i = 0 ; i < length ; i++){
				if(i % 2){
					buffer[i] = 65 + (u_int32_t) (26.0 * rand() / (RAND_MAX + 1.0));
				} else {
					buffer[i] = 97 + (u_int32_t) (26.0 * rand() / (RAND_MAX + 1.0));
				}
			}
			break;
		default:
			printf("unknown options %d processing strings\n", choice);
			exit(EXIT_FAILURE);
			break;
	}

	buffer[length - 1] = '\0';
	
	return(buffer);
}

/* Usage help message. 
   Returns the usage to process_options(). */
void usage(int8_t * program, int8_t * author, int8_t * email){
	printf("ENG v%s.%s - Encore Project Next Generation (Private Morphic Tool)\n", __MAJOR_VERSION, __MINOR_VERSION);
	printf("%s <%s>\n\n", author, email);
	printf("Usage:  %s -h [options]\n\n", program);
	printf("Common Options:\n");
	printf("  -h, --help            display this help and exit\n");
	printf("      --copyright       display copyright statement\n\n");
	printf("IP Options:\n");
	printf("  -d, --daddr ADDRESS   destination IP address\n");
#ifndef __CYGWIN__
	printf("  -s, --saddr ADDRESS   source IP address (default is RANDOM)\n");
	printf("      --source PORT     source UDP port (default is %d)\n", IPPORT_DEFAULT);
	printf("                        \'--source 0\' is RANDOM UDP source port\n");
	printf("      --ttl TTL         IP time to live (default is 255)\n");
	printf("      --tos TOS         IP type of service (default is %d)\n", IPTOS_PREC_IMMEDIATE);
	printf("      --id IPID         IP ID (default is getpid())\n\n");
#else   /* __CYGWIN__ */
	printf("\n");
#endif  /* __CYGWIN__ */
	printf("Payload Options:\n");
	printf("      --port PORT       shellcode BIND port (default is %d)\n", DEFAULT_CMD_PORT);
	printf("      --shellcode ID    false-negative shellcode (default is %d)\n", DEFAULT_SHELLCODE_ID);
	printf("      --offset ID       false-negative offset (default is %d)\n", SQL_PUB_OFFSET);
	printf("  -S, --list-shellcode  display all available shellcodes\n");
	printf("  -O, --list-offset     display all available offsets\n\n");
	printf("Alpha2.c %s <%s>.\n", __ALPHA2_COPYRIGHT, __ALPHA2_AUTHOR_MAIL);
	printf("%s\n\n", __ALPHA2_VERSION);
	printf("ENG v%s.%s Copyright© 2004-2008 %s <%s>.\n", __MAJOR_VERSION, __MINOR_VERSION, author, email);
	printf("All rights reserved worldwide.\n");
	exit(EXIT_FAILURE);
}
#endif  /* UTILS__C_ */
