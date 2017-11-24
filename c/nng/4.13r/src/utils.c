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
#ifndef UTILS_C__
#define UTILS_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: utils.c,v 1.1 2008-09-13 13:42:46-03 nbrito Exp $ */
#include "common.h" 

/* Packet's check summing routine.
   Returns the checksum to sendraw().  */
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

/* Usage help message. 
   Returns the usage to process_options(). */
void usage(int8_t * program, int8_t * author, int8_t * email){
	printf("NNG v%s.%s - Numb Project Next Generation (Private False-Positive Tool)\n", __MAJOR_VERSION, __MINOR_VERSION);
	printf("%s <%s>\n\n", author, email);
	printf("Usage:  %s -h [options]\n\n", program);
	printf("Common Options:\n");
	printf("  -h, --help            display this help and exit\n");
	printf("      --copyright       display Copyright Statement\n");
	printf("      --threshold NUM   threshold of events to be reached (default is 1,000)\n");
	printf("      --flood           flood the target, this mode supersedes the \'--threshold\'\n");
	printf("      --delay NUM       delay in milliseconds (default is 1)\n\n");
	printf("IP Options:\n");
	printf("  -s, --saddr ADDRESS   source IP address (default is RANDOM)\n");
#ifdef __CYGWIN__
        printf("                        WinXP SP2 only allows you spoof 127.0.0.0/8\n");
#endif /* __CYGWIN__ */
	printf("  -d, --daddr ADDRESS   destination IP address\n");
	printf("      --ttl NUM         IP time to live (default is 255)\n");
	printf("      --tos NUM         IP type of service (default is IPTOS_PREC_IMMEDIATE)\n");
	printf("      --id NUM          IP ID (default is getpid())\n\n");
	printf("NIPS Options:\n");
	printf("      --list            display all available false-positives payloads\n");
	printf("      --payload NUM     NIPS false-positive payload (default is ALL)\n\n");
	printf("NNG v%s.%s Copyright© 2004-2008 %s <%s>.\n", __MAJOR_VERSION, __MINOR_VERSION, author, email);
	printf("All rights reserved worldwide.\n");
	exit(EXIT_FAILURE);
}
#endif  /* UTILS_C__ */
