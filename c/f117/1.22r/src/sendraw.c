/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the F117 Private Tool by Nelson Brito.

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
#ifndef SENDRAW_C__
#define SENDRAW_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: sendraw.c,v 1.1 2008-09-12 15:36:14-03 nbrito Exp $ */
#include "common.h"

/* Raw packet sending routine. 
   Returns the status of sendto(). */
const int32_t sendraw(register int32_t sock, struct options options){
	int32_t status;           /* status to be returned */
	struct  timeval  seed;    /* seed for random       */
	struct  sockaddr_in sin;  /* socket address        */
	struct  iphdr  * ip;      /* IP header             */ 
	struct  tcphdr * tcp;     /* TCP header            */
	struct  psdhdr * pseudo;  /* PSEUDO header         */

	/* Making unquestionable the false-positive.     */
	u_int8_t   packet[IPHDR_SIZE + TCPHDR_SIZE];
	u_int8_t   checksum[PSDHDR_SIZE + TCPHDR_SIZE];

	/* Setting SOCKADDR structure. */
        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(options.dest);
        sin.sin_addr.s_addr = options.daddr;

	/* Using microseconds as seed. */
	gettimeofday(&seed, (struct timezone *)0);
	srand((unsigned) seed.tv_usec);
					
	/* Packet making a pointer to IP Header structure. */
	ip              = (struct iphdr *) packet;
	ip->version     = IPVERSION;
	ip->ihl         = IPHDR_SIZE/4;
	ip->tos	        = options.tos;
	ip->frag_off    = 0x00;
	ip->tot_len     = htons(IPHDR_SIZE + TCPHDR_SIZE);
	ip->id          = htons(options.id);
	ip->ttl         = options.ttl;
	ip->protocol    = IPPROTO_TCP;
	ip->saddr       = INADDR_RND(options.saddr);
	ip->daddr       = options.daddr;
	ip->check       = in_cksum((u_int16_t *)&ip, htons(ip->tot_len));

	/* Packet making a pointer to TCP Header structure. */
	tcp             = (struct tcphdr *)(packet + IPHDR_SIZE);
	tcp->source     = htons(IPPORT_RND(options.source)); 
	tcp->dest       = htons(IPPORT_RND(options.dest));
	tcp->seq        = ((rand() & 0xffffffff) << 31) + (rand() & 0xffffffff);
	tcp->ack_seq    = ((rand() & 0xffffffff) << 31) + (rand() & 0xffffffff);
	tcp->res1       = 0x00;
	tcp->doff       = TCPHDR_SIZE/4;
	tcp->fin        = options.fin ? options.fin : 0x00;
	tcp->syn        = options.syn ? options.syn : 0x00;
	tcp->rst        = options.rst ? options.rst : 0x00;
	tcp->psh        = options.psh ? options.psh : 0x00;
	tcp->ack        = options.ack ? options.ack : 0x00;
	tcp->urg        = options.urg ? options.urg : 0x00;
	tcp->urg_ptr    = options.urg ? options.urg : 0x00;
	tcp->window     = htons((TCPHDR_SIZE/5)*512);
	tcp->check      = 0;

	/* Building the Checksum Packet.
	   Zeroing the content of the checksum. */
	memset(&checksum, 0, sizeof(checksum));
	
	/* Checksum Packet making a pointer to PSEUDO Header structure. */
	pseudo          = (struct psdhdr *)(checksum);
	pseudo->saddr   = ip->saddr;
	pseudo->daddr   = ip->daddr;
	pseudo->zero    = 0;
	pseudo->protocol= ip->protocol;
	pseudo->len     = htons(TCPHDR_SIZE);
	
	/* Copying the TCP header to the checksum. */
	memcpy(checksum + PSDHDR_SIZE, tcp, TCPHDR_SIZE);

	/* Computing the checksum. */
	tcp->check      = in_cksum((u_int16_t *)&checksum, TCPHDR_SIZE + PSDHDR_SIZE);

	/* Sending packet. */
	status = sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *) &sin, sizeof(struct sockaddr));

	/* Returning the status. */
	return(status);
}
#endif  /* SENDRAW_C__ */
