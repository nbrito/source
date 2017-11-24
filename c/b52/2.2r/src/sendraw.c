/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the B52 Private Tool by Nelson Brito.

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
   $Id: sendraw.c,v 1.1 2008-08-23 10:06:09-03 nbrito Exp $ */
#include "common.h"

/* Raw packet sending routine. 
   Returns the status of sendto(). */
const int32_t sendraw(register int32_t sock, struct options options){
	int32_t status;           /* status to be returned */
	int32_t c = 0;            /* simple counter        */
	struct  timeval  seed;    /* seed for random       */
	struct  sockaddr_in sin;  /* socket address        */
	struct  iphdr  * ip;      /* IP header             */ 
	struct  udphdr * udp;     /* UDP header            */
	struct  psdhdr * pseudo;  /* PSEUDO header         */

	/* Making unquestionable the false-positive.     */
	u_int8_t   data[options.length];
	u_int8_t   packet[IPHDR_SIZE + UDPHDR_SIZE + sizeof(data)];
	u_int8_t   checksum[PSDHDR_SIZE + UDPHDR_SIZE + sizeof(data)];

	/* Setting SOCKADDR structure. */
        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(options.dest);
        sin.sin_addr.s_addr = options.daddr;

	/* Building the Packet.
	   Zeroing the content of the Packet. */
	memset(&packet, 0, sizeof(packet));

	/* Packet making a pointer to IP Header structure. */
	ip              = (struct iphdr *) packet;
	ip->version     = IPVERSION;
	ip->ihl         = IPHDR_SIZE/4;
	ip->tos	        = options.tos;
	ip->tot_len     = htons(IPHDR_SIZE + UDPHDR_SIZE + sizeof(data));
	ip->id          = htons(options.id);
	ip->ttl         = options.ttl;
	ip->protocol    = IPPROTO_UDP;
	ip->saddr       = INADDR_RND(options.saddr);
	ip->daddr       = options.daddr;
	ip->check       = in_cksum((u_int16_t *)&ip, htons(ip->tot_len));

	/* Packet making a pointer to UDP Header structure. */
	udp             = (struct udphdr *)(packet + IPHDR_SIZE);
	udp->source     = htons(IPPORT_RND(options.source)); 
	udp->dest       = htons(IPPORT_RND(options.dest));
	udp->len        = htons(UDPHDR_SIZE + sizeof(data));
	udp->check      = 0;

	/* Building the Data Field.
	   Zeroing the content of the Data Field. */
	memset(&data,0, sizeof(data));

	while(c < options.length){
		/* Using microseconds as seed. */
		gettimeofday(&seed, (struct timezone *)0);
		srand((unsigned) seed.tv_usec);
		
		data[c] = 1 + (u_int32_t) (127.0 * rand() / (RAND_MAX + 1.0));
		
		c++;
	}
	/* Copying the Data Field to the Packet. */
	memcpy(packet + IPHDR_SIZE + UDPHDR_SIZE, data, sizeof(data));

	/* Building the Checksum Packet.
	   Zeroing the content of the checksum. */
	memset(&checksum, 0, sizeof(checksum));
	
	/* Checksum Packet making a pointer to PSEUDO Header structure. */
	pseudo          = (struct psdhdr *)(checksum);
	pseudo->saddr   = ip->saddr;
	pseudo->daddr   = ip->daddr;
	pseudo->zero    = 0;
	pseudo->protocol= ip->protocol;
	pseudo->len     = htons(UDPHDR_SIZE + sizeof(data));
	
	/* Copying the UDP header to the checksum. */
	memcpy(checksum + PSDHDR_SIZE, udp, UDPHDR_SIZE);

	/* Copying the data field to checksum. */
	memcpy(checksum + PSDHDR_SIZE + UDPHDR_SIZE, data, sizeof(data));

	/* Computing the checksum. */
	udp->check      = in_cksum((u_int16_t *)&checksum, UDPHDR_SIZE + PSDHDR_SIZE + sizeof(data));

	/* Sending packet. */
	status = sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *) &sin, sizeof(struct sockaddr));

	/* Returning the status. */
	return(status);
}
#endif  /* SENDRAW_C__ */
