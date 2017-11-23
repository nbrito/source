/* 
 * $Id: udp.c,v 3.6 2010-11-27 14:48:12-02 nbrito Exp $
 */

/* ------------------x------------------x------------------x------------------
 * Author: Nelson Brito <nbrito[at]sekure[dot]org>
 *
 * Copyright (c) 2001-2010 Nelson Brito. All rights reserved worldwide.
 *
 * This software and its codes may be provided as  source code but IS NOT
 * LICENSED under the GPL or any other common Open Source licenses.
 * ------------------x------------------x------------------x------------------

                    T50: an Experimental Packet Injector Tool
                                  Release 2.45

                      Copyright (c) 2001-2010 Nelson Brito
                               All Rights Reserved

     T50 IS AN EXPERIMENTAL SOFTWARE  AND IS KNOWN TO CAUSE SERIOUS DAMAGES
     IN COMPUTER SYSTEMS, SOME OF WHICH MAY BE IN VIOLATION OF FEDERAL LAW,
     INCLUDING  THE  COMPUTER  FRAUD  AND  ABUSE  ACT  AND  OTHER  RELEVANT
     PROVISIONS OF FEDERAL CIVIL AND CRIMINAL LAW.  VIOLATION WILL / CAN BE
     SUBJECT  TO  CIVIL  AND  CRIMINAL  PENALTIES  INCLUDING CIVIL MONETARY
     PENALTIES.

     THIS SOFTWARE  IS PROVIDED  ``AS IS'',  WITHOUT  WARRANTY OF ANY KIND,
     EXPRESS  OR  IMPLIED, INCLUDING BUT NOT  LIMITED  TO THE WARRANTIES OF
     MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
     IN NO  EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS  BE LIABLE FOR ANY
     CLAIM, DAMAGES  OR OTHER LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,
     TORT  OR OTHERWISE,  ARISING FROM,  OUT OF  OR IN CONNECTION  WITH THE
     SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
   
   ------------------x------------------x------------------x------------------ */
#ifndef UDP_C__
#define UDP_C__ 1

#include <common.h>


/* Local Global Variables. */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 3.6 $";
#endif  /* __HAVE_DEBUG__ */


/* Function Name: UDP packet header configuration.

   Description:   This function configures and sends the UDP packet header.

   Targets:       N/A */
inline const void * udp(const socket_t fd, const struct config_options o){
	/* Packet size. */
	const u_int32_t packet_size = sizeof(struct iphdr) + sizeof(struct udphdr);
	/* Packet and checksum. */
	u_int8_t packet[packet_size], checksum[packet_size];
	/* Socket address, IP header, TCP header and PSEUDO header. */
	static struct sockaddr_in sin;
	static struct iphdr  * ip;
	static struct udphdr * udp;
	static struct psdhdr * pseudo;

	/* Setting SOCKADDR structure. */
        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(IPPORT_RND(o.dest));
        sin.sin_addr.s_addr = o.ip.daddr;

	/* Packet making a pointer to IP Header structure. */
	ip              = (struct iphdr *) packet;
	ip->version     = IPVERSION;
	ip->ihl         = sizeof(struct iphdr)/4;
	ip->tos	        = o.ip.tos;
	ip->frag_off    = o.ip.frag_off ? htons((o.ip.frag_off >> 3) | IP_MF) : htons(o.ip.frag_off | IP_DF);
	ip->tot_len     = htons(packet_size);
	ip->id          = __16BIT_RND(o.ip.id);
	ip->ttl         = o.ip.ttl;
	ip->protocol    = o.ip.protocol;
	ip->saddr       = INADDR_RND(o.ip.saddr);
	ip->daddr       = o.ip.daddr;
	ip->check       = cksum((u_int16_t *)&ip, htons(ip->tot_len));

	/* Packet making a pointer to UDP Header structure. */
	udp             = (struct udphdr *)(packet + sizeof(struct iphdr));
	udp->source     = htons(IPPORT_RND(o.source)); 
	udp->dest       = htons(IPPORT_RND(o.dest));
	udp->len        = htons(sizeof(struct udphdr));
	udp->check      = o.bogus_csum ? 1 + (u_int32_t) (65535.0 * rand() / (RAND_MAX + 1.0)) : 0;

	/* Checking 'B[ogus|ad]' checksum. */
	if(o.bogus_csum == 0){
		/* Checksum Packet making a pointer to PSEUDO Header structure. */
		pseudo           = (struct psdhdr *)(checksum);
		pseudo->saddr    = ip->saddr;
		pseudo->daddr    = ip->daddr;
		pseudo->zero     = 0;
		pseudo->protocol = ip->protocol;
		pseudo->len      = htons(sizeof(struct udphdr));
	
		/* Copying the TCP header to the checksum. */
		memcpy(checksum + sizeof(struct psdhdr), udp, sizeof(struct udphdr));
		/* Computing the checksum. */
		udp->check       = cksum((u_int16_t *)&checksum, sizeof(struct udphdr) + sizeof(struct psdhdr));
	}

	/* Sending packet. */
	if(sendto(fd, &packet, packet_size, 0|MSG_NOSIGNAL, (struct sockaddr *) &sin, sizeof(struct sockaddr)) == -1){ //&& errno != EPERM){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		perror("sendto()");
		/* Closing the socket. */
		close(fd);
		/* Exiting. */
		exit(EXIT_FAILURE);
	}

	return(0);
}
#endif  /* UDP_C__ */
