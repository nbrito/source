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
#ifndef SENDRAW_C__
#define SENDRAW_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: sendraw.c,v 1.1 2008-09-13 13:42:46-03 nbrito Exp $ */
#include "common.h"

/* Raw packet sending routine. 
   Returns the status of sendto(). */
const int32_t sendraw(register int32_t sock, struct options options, struct payload payload){
	int32_t status;           /* status to be returned */
	struct  timeval  seed;    /* seed for random       */
	struct  sockaddr_in sin;  /* socket address        */
#ifdef __CYGWIN__
	struct  ip     * ip;      /* IP header             */ 
#else  /* __CYGWIN__ */
	struct  iphdr  * ip;      /* IP header             */ 
#endif /* __CYGWIN__ */
	struct  udphdr * udp;     /* UDP header            */
	struct  psdhdr * pseudo;  /* PSEUDO header         */

	/* Making unquestionable the false-positive.     */
	u_int8_t * evidence = " nng ",
	/* Setting the size of Data Field and Packet. */
		   data[payload.size + strlen(evidence) + strlen(payload.nips)],
	/* Setting the size of Packet. */
		   packet[IPHDR_SIZE + UDPHDR_SIZE + sizeof(data)],
	/* Setting the size of Checksum. */
		   checksum[PSDHDR_SIZE + UDPHDR_SIZE + sizeof(data)];

	/* Setting SOCKADDR structure. */
        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(payload.dest);
        sin.sin_addr.s_addr = options.daddr;

	/* Using microseconds as seed. */
	gettimeofday(&seed, (struct timezone *)0);
	srand((unsigned) seed.tv_usec);
	
	/* Building the Packet.
	   Zeroing the content of the Packet. */
	memset(&packet, 0, sizeof(packet));

	/* Packet making a pointer to IP Header structure. */
#ifdef __CYGWIN__
	ip                = (struct ip *) packet;
	ip->ip_v          = IPVERSION;
	ip->ip_hl         = IPHDR_SIZE/4;
	ip->ip_tos        = options.tos;
	ip->ip_len        = htons(IPHDR_SIZE + UDPHDR_SIZE + sizeof(data));
	ip->ip_id         = htons(options.id);
	ip->ip_ttl        = options.ttl;
	ip->ip_p          = payload.protocol;
	ip->ip_src.s_addr = INADDR_RND(options.saddr);
	ip->ip_dst.s_addr = options.daddr;
	ip->ip_sum        = in_cksum((u_int16_t *)&ip, htons(ip->ip_len));
#else  /* __CYGWIN__ */
	ip                = (struct iphdr *) packet;
	ip->version       = IPVERSION;
	ip->ihl           = IPHDR_SIZE/4;
	ip->tos           = options.tos;
	ip->tot_len       = htons(IPHDR_SIZE + UDPHDR_SIZE + sizeof(data));
	ip->id            = htons(options.id);
	ip->ttl           = options.ttl;
	ip->protocol      = payload.protocol;
	ip->saddr         = INADDR_RND(options.saddr);
	ip->daddr         = options.daddr;
	ip->check         = in_cksum((u_int16_t *)&ip, htons(ip->tot_len));
#endif /* __CYGWIN__ */

	/* Packet making a pointer to UDP Header structure. */
#ifdef __CYGWIN__
	udp               = (struct udphdr *)(packet + IPHDR_SIZE);
	udp->uh_sport     = htons(IPPORT_RND(payload.source)); 
	udp->uh_dport     = htons(IPPORT_RND(payload.dest));
	udp->uh_ulen      = htons(UDPHDR_SIZE + sizeof(data));
	udp->uh_sum       = 0;
#else  /* __CYGWIN__ */
	udp               = (struct udphdr *)(packet + IPHDR_SIZE);
	udp->source       = htons(IPPORT_RND(payload.source)); 
	udp->dest         = htons(IPPORT_RND(payload.dest));
	udp->len          = htons(UDPHDR_SIZE + sizeof(data));
	udp->check        = 0;
#endif /* __CYGWIN__ */

	/* Building the Data Field.
	   Zeroing the content of the Data Field. */
	memset(&data,0, sizeof(data));

	/* Copying the payload to Data Field. */
	memcpy(data, \
		payload.payload, \
		payload.size);

	/* Copying the evidence to Data Field. */
	memcpy(data \
			+ payload.size, 
		evidence, \
		strlen(evidence));

	/* Copying the NIPS name to Data Field. */
	memcpy(data \
			+ payload.size \
			+ strlen(evidence), \
		payload.nips, \
		strlen(payload.nips));

	/* Copying the Data Field to the Packet. */
	memcpy(packet \
			+ IPHDR_SIZE \
			+ UDPHDR_SIZE, \
		data, \
		sizeof(data));

	/* Building the Checksum Packet.
	   Zeroing the content of the checksum. */
	memset(&checksum, 0, sizeof(checksum));
	
	/* Checksum Packet making a pointer to PSEUDO Header structure. */
	pseudo            = (struct psdhdr *)(checksum);
#ifdef __CYGWIN__
	pseudo->saddr     = ip->ip_src.s_addr;
	pseudo->protocol  = ip->ip_p;
	pseudo->daddr     = ip->ip_dst.s_addr;
#else  /* __CYGWIN__ */
	pseudo->saddr     = ip->saddr;
	pseudo->protocol  = ip->protocol;
	pseudo->daddr     = ip->daddr;
#endif /* __CYGWIN__ */
	pseudo->zero      = 0;
	pseudo->len       = htons(UDPHDR_SIZE + sizeof(data));
	
	/* Copying the UDP header to the checksum. */
	memcpy(checksum + PSDHDR_SIZE, udp, UDPHDR_SIZE);

	/* Copying the data field to checksum. */
	memcpy(checksum + PSDHDR_SIZE + UDPHDR_SIZE, data, sizeof(data));

	/* Computing the checksum. */
#ifdef __CYGWIN__
	udp->uh_sum       = in_cksum((u_int16_t *)&checksum, \
		       			UDPHDR_SIZE \
					+ PSDHDR_SIZE \
					+ sizeof(data));
#else  /* __CYGWIN__ */
	udp->check        = in_cksum((u_int16_t *)&checksum, \
		       			UDPHDR_SIZE \
					+ PSDHDR_SIZE \
					+ sizeof(data));
#endif /* __CYGWIN__ */

	/* Sending packet. */
	status = sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *) &sin, sizeof(struct sockaddr));

	/* Returning the status. */
	return(status);
}
#endif  /* SENDRAW_C__ */
