/* 
 * $Id: eigrp.c,v 5.37 2011-04-17 11:38:38-03 nbrito Exp $
 */

/***************************************************************************
  ___________._______________
  \__    ___/|   ____/\   _  \   T50: an Experimental Packet Injector Tool
    |    |   |____  \ /  /_\  \                 Release 5.3
    |    |   /       \\  \_/   \
    |____|  /______  / \_____  /   Copyright (c) 2001-2011 Nelson Brito
                   \/        \/             All Rights Reserved

 ***************************************************************************
 * Author: Nelson Brito <nbrito@sekure.org>                                *
 *                                                                         *
 * Copyright (c) 2001-2011 Nelson Brito. All rights reserved worldwide.    *
 *                                                                         *
 * The following text was taken borrowed from Nmap License.                *
 ************************IMPORTANT T50 LICENSE TERMS************************
 *                                                                         *
 * T50 is program is free software;  you may redistribute and/or modify it *
 * under the terms of the 'GNU General Public License' as published by the *
 * Free  Software  Foundation;  Version  2  with  the  clarifications  and *
 * exceptions described below.  This guarantees your right to use, modify, *
 * and redistribute this software under certain conditions. If you wish to *
 * embed T50 technology into  proprietary software,  please,  contact  the *
 * author for an alternative license (contact nbrito@sekure.org).          *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it  does  not provide a  detailed  definition of  that  term.  To avoid *
 * misunderstandings, the author considers an application  to constitute a *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * 1 Integrates source code from T50.                                      *
 * 2 Reads or includes T50 copyrighted data files, such: protocol modules, *
 *   configuration files or libraries.                                     *
 * 3 Integrates, includes or aggregates  T50 into a proprietary executable *
 *   installer, such as those produced by InstallShield.                   *
 * 4 Links to a library or executes a program that does any of the above.  *
 *                                                                         *
 * The term "T50" should be  taken to also include any portions or derived *
 * works of T50.  This list is not exclusive,  but is meant to clarify the *
 * author's interpretation  of  "derived works" with some common examples. *
 * The author's interpretation applies only to T50 -- he doesn't speak for *
 * other people's GPL works.                                               *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * T50 in non-GPL works,  the author would be happy to help.  As mentioned *
 * above, the author also offers alternative license to integrate T50 into *
 * proprietary  applications  and  appliances.  These  licenses  generally *
 * include  a  perpetual license as well as providing for priority support *
 * and updates as well as helping to fund the continued development of T50 *
 * technology.  Please email nbrito@sekure.org for further information.    *
 *                                                                         *
 * If  you  received these files  with  a  written  license  agreement  or *
 * contract  stating   terms  other   than  the  terms  above,  then  that *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to  this software because the author  believes users *
 * have a right to know exactly what a program  is going to do before they *
 * run it.  This also allows you to audit the software for security holes, *
 * but none have been found so far.                                        *
 *                                                                         *
 * Source code also allows you to port T50 to new platforms, fix bugs, and *
 * add new features and new protocol modules. You are highly encouraged to *
 * send your changes to nbrito@sekure.org for possible  incorporation into *
 * the main distribution. By sending these changes to Nelson Brito,  it is *
 * assumed  that you are  offering the  T50 Project,  and its author,  the *
 * unlimited,  non-exclusive right to reuse,  modify,  and  relicense  the *
 * code.  T50 will always be available Open Source,  but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects  (such  as  KDE and NASM).  The author *
 * also  occasionally  relicense  the  code  to third parties as discussed *
 * above.  If  you wish to  specify  special license  conditions  of  your *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This  program  is distributed in the hope that it will  be useful,  but *
 * WITHOUT  ANY  WARRANTY;    without   even   the   implied  warranty  of *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    *
 * Please, refer to GNU General Public License v2.0 for further details at *
 * http://www.gnu.org/licenses/gpl-2.0.html,  or  in the  LICENSE document *
 * included with T50.                                                      *
 ***************************************************************************/
#ifndef EIGRP_C__
#define EIGRP_C__ 1

#include <common.h>


/*
 * External prototypes.
 */
extern inline size_t eigrp_hdr_len(const u_int16_t, const u_int16_t, const u_int8_t, const u_int32_t);
extern inline size_t gre_opt_len(const u_int8_t, const u_int8_t);


/* 
 * Local Global Variables.
 */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 5.37 $";
#endif  /* __HAVE_DEBUG__ */


/* Function Name: EIGRP packet header configuration.

   Description:   This function configures and sends the EIGRP packet header.

   Targets:       N/A */
inline const void * eigrp(const socket_t fd, const struct config_options o){
	/* GRE options size. */
	size_t greoptlen = gre_opt_len(o.gre.options, o.encapsulated);
	/* EIGRP Destination Address and Prefix. */
	in_addr_t dest = INADDR_RND(o.eigrp.dest);
	/* Must compute the EIGRP Destination Prefix here. */
	u_int32_t prefix = __5BIT_RND(o.eigrp.prefix);
	/* EIGRP TLV size. */
	size_t eigrp_tlv_len = eigrp_hdr_len(o.eigrp.opcode, o.eigrp.type, prefix, o.eigrp.auth);
	/* Packet size. */
	const u_int32_t packet_size = sizeof(struct iphdr)     + \
	                              greoptlen                + \
	                              sizeof(struct eigrp_hdr) + \
				      eigrp_tlv_len;
	/* Checksum offset, GRE offset and Counter. */
	static u_int32_t offset = 0, greoffset = 0, counter = 0;
	/* Packet and Checksum. */
	u_int8_t packet[packet_size], * checksum = NULL;
	/* Socket address and IP header. */
	static struct sockaddr_in sin;
	static struct iphdr * ip;
	/* GRE header, GRE Checksum header and GRE Encapsulated IP Header. */
	static struct gre_hdr * gre;
	static struct gre_sum_hdr * gre_sum;
	static struct gre_key_hdr * gre_key;
	static struct gre_seq_hdr * gre_seq;
	static struct iphdr * gre_ip;
	/* EIGRP header. */
	static struct eigrp_hdr * eigrp;

	/* Setting SOCKADDR structure. */
	sin.sin_family      = AF_INET;
	sin.sin_port        = htons(IPPORT_RND(o.dest));
	sin.sin_addr.s_addr = o.ip.daddr;

	/* IP Header structure making a pointer to Packet. */
	ip           = (struct iphdr *)packet;
	ip->version  = IPVERSION;
	ip->ihl      = sizeof(struct iphdr)/4;
	ip->tos	     = o.ip.tos;
	ip->frag_off = htons(o.ip.frag_off ? \
		               (o.ip.frag_off >> 3) | IP_MF : \
	               o.ip.frag_off | IP_DF);
	ip->tot_len  = htons(packet_size);
	ip->id       = htons(__16BIT_RND(o.ip.id));
	ip->ttl      = o.ip.ttl;
	ip->protocol = o.encapsulated ? \
		               IPPROTO_GRE : \
	               o.ip.protocol;
	ip->saddr    = INADDR_RND(o.ip.saddr);
	ip->daddr    = o.ip.daddr;
	/* The code does not have to handle this, Kernel will do. */
	ip->check    = 0;

	/* Computing the GRE Offset. */
	greoffset = sizeof(struct iphdr);

	/* GRE Encapsulation takes place. */
	if(o.encapsulated){
		/* GRE Header structure making a pointer to IP Header structure. */
		gre          = (struct gre_hdr *)((u_int8_t *)ip + greoffset);
		gre->C       = (o.gre.options & GRE_OPTION_CHECKSUM) == GRE_OPTION_CHECKSUM ? \
			               1 : \
		               0;
		gre->K       = (o.gre.options & GRE_OPTION_KEY) == GRE_OPTION_KEY ? \
			               1 : \
		               0;
		gre->R       = FIELD_MUST_BE_ZERO;
		gre->S       = (o.gre.options & GRE_OPTION_SEQUENCE) == GRE_OPTION_SEQUENCE ? \
			               1 : \
		               0;
		gre->s       = FIELD_MUST_BE_ZERO;
		gre->recur   = FIELD_MUST_BE_ZERO;
		gre->version = GREVERSION;
		gre->flags   = FIELD_MUST_BE_ZERO;
		gre->proto   = htons(ETH_P_IP);
		/* Computing the GRE offset. */
		greoffset  += sizeof(struct gre_hdr);

		/* GRE CHECKSUM? */
		if((o.gre.options & GRE_OPTION_CHECKSUM) == GRE_OPTION_CHECKSUM){
			/* GRE CHECKSUM Header structure making a pointer to IP Header structure. */
			gre_sum         = (struct gre_sum_hdr *)((u_int8_t *)ip + greoffset);
			gre_sum->offset = FIELD_MUST_BE_ZERO;
			gre_sum->check  = 0;
			/* Computing the GRE offset. */
			greoffset += GRE_OPTLEN_CHECKSUM;
		}

		/* GRE KEY? */
		if((o.gre.options & GRE_OPTION_KEY) == GRE_OPTION_KEY){
			/* GRE KEY Header structure making a pointer to IP Header structure. */
			gre_key      = (struct gre_key_hdr *)((u_int8_t *)ip + greoffset);
			gre_key->key = htonl(__32BIT_RND(o.gre.key));
			/* Computing the GRE offset. */
			greoffset += GRE_OPTLEN_KEY;
		}

		/* GRE SEQUENCE? */
		if((o.gre.options & GRE_OPTION_SEQUENCE) == GRE_OPTION_SEQUENCE){
			/* GRE SEQUENCE Header structure making a pointer to IP Header structure. */
			gre_seq          = (struct gre_seq_hdr *)((u_int8_t *)ip + greoffset);
			gre_seq->sequence = htonl(__32BIT_RND(o.gre.sequence));
			/* Computing the GRE offset. */
			greoffset += GRE_OPTLEN_SEQUENCE;
		}

		/*
		 * Generic Routing Encapsulation over IPv4 networks (RFC 1702)
		 *
		 * IP as both delivery and payload protocol
		 *
		 * When IP is encapsulated in IP,  the TTL, TOS,  and IP security options
		 * MAY  be  copied from the payload packet into the same  fields  in  the
		 * delivery packet. The payload packet's TTL MUST be decremented when the
		 * packet is decapsulated to insure that no packet lives forever.
		 */
		/* GRE Encapsulated IP Header structure making a pointer to to IP Header structure. */
		gre_ip           = (struct iphdr *)((u_int8_t *)ip + greoffset);
		gre_ip->version  = ip->version;
		gre_ip->ihl      = ip->ihl;
		gre_ip->tos      = ip->tos;
		gre_ip->frag_off = ip->frag_off;
		gre_ip->tot_len  = htons(sizeof(struct iphdr) + \
	                           sizeof(struct eigrp_hdr) + \
				   eigrp_tlv_len);
		gre_ip->id       = ip->id;
		gre_ip->ttl      = ip->ttl;
		gre_ip->protocol = o.ip.protocol;
		gre_ip->saddr    = o.gre.saddr ? \
			                   o.gre.saddr : \
		                    ip->saddr;
		gre_ip->daddr    = o.gre.daddr ? \
			                   o.gre.daddr : \
		                    ip->daddr;
		/* Computing the checksum. */
		gre_ip->check    = 0;
		gre_ip->check    = o.bogus_csum ? \
				           __16BIT_RND(0) : \
			           cksum((u_int16_t *)gre_ip, sizeof(struct iphdr));

		/* Computing the GRE offset. */
		greoffset += sizeof(struct iphdr);
	}

	/* 
	 * Please,  be advised that there is no deep information about EIGRP,  no
	 * other than EIGRP PCAP files public available.  Due to that I have done
	 * a deep analysis using live EIGRP PCAP files to build the EIGRP Packet.
	 *
	 * There are some really good resources, such as:
	 * http://www.protocolbase.net/protocols/protocol_EIGRP.php
	 * http://packetlife.net/captures/category/cisco-proprietary/
	 * http://oreilly.com/catalog/iprouting/chapter/ch04.html
	 *
	 * EIGRP Header structure making a pointer to IP Header structure.
	 */
	eigrp              = (struct eigrp_hdr *)((u_int8_t *)ip + sizeof(struct iphdr) + greoptlen);
	eigrp->version     = o.eigrp.ver_minor ? \
		                     o.eigrp.ver_minor : \
	                     EIGRPVERSION;
	eigrp->opcode      = __8BIT_RND(o.eigrp.opcode);
	eigrp->flags       = htonl(__32BIT_RND(o.eigrp.flags));
	eigrp->sequence    = htonl(__32BIT_RND(o.eigrp.sequence));
	eigrp->acknowledge = o.eigrp.type == EIGRP_TYPE_SEQUENCE ? \
		                     htonl(__32BIT_RND(o.eigrp.acknowledge)) : \
	                     0;
	eigrp->as          = htonl(__32BIT_RND(o.eigrp.as));
	eigrp->check       = 0;
	/* Computing the Checksum offset. */
	offset  = sizeof(struct eigrp_hdr);

	/* Storing both Checksum and Packet. */
	checksum = (u_int8_t *)eigrp + offset;

	/*
	 * Every live EIGRP PCAP file brings Authentication Data TLV first.
	 *
	 * The Authentication Data TVL must be used only in some cases:
	 * 1. IP Internal or External Routes TLV for Update
	 * 2. Software Version with Parameter TLVs for Hello
	 * 3. Next Multicast Sequence TLV for Hello
	 */
	if(o.eigrp.auth){
		if(o.eigrp.opcode == EIGRP_OPCODE_UPDATE  ||
		  (o.eigrp.opcode == EIGRP_OPCODE_HELLO   &&
		  (o.eigrp.type   == EIGRP_TYPE_MULTICAST ||
		   o.eigrp.type   == EIGRP_TYPE_SOFTWARE))){
			/*
			 * Enhanced Interior Gateway Routing Protocol (EIGRP)
			 *
			 * Authentication Data TLV  (EIGRP Type = 0x0002)
			 *
			 *    0                   1                   2                   3 3
			 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *   |             Type              |            Length             |
			 *   +---------------------------------------------------------------+
			 *   |     Authentication Method     |    Authentication Key Size    |
			 *   +---------------------------------------------------------------+
			 *   |                     Authentication Key ID                     |
			 *   +---------------------------------------------------------------+
			 *   |                                                               |
			 *   +                                                               +
			 *   |                          Padding (?)                          |
			 *   +                                                               +
			 *   |                                                               |
			 *   +---------------------------------------------------------------+
			 *   |                                                               |
			 *   +                                                               +
			 *   |                    Authentication Key Block                   |
			 *   +                          (MD5 Digest)                         +
			 *   |                                                               |
			 *   +                                                               +
			 *   |                                                               |
			 *   +---------------------------------------------------------------+
			 */
			*((u_int16_t *)checksum) = htons(EIGRP_TYPE_AUTH);
			checksum += sizeof(u_int16_t);
			*((u_int16_t *)checksum) = htons(o.eigrp.length ? \
				                           o.eigrp.length : \
			                           EIGRP_TLEN_AUTH);
			checksum += sizeof(u_int16_t);
			*((u_int16_t *)checksum) = htons(AUTH_TYPE_HMACMD5);
			checksum += sizeof(u_int16_t);
			*((u_int16_t *)checksum) = htons(auth_hmac_md5_len(o.eigrp.auth));
			checksum += sizeof(u_int16_t);
			*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.eigrp.key_id));
			checksum += sizeof(u_int32_t);
			for(counter = 0 ; counter < EIGRP_PADDING_BLOCK ; counter++)
				*checksum++ = FIELD_MUST_BE_ZERO;
			/*
			 * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
			 */
			for(counter = 0 ; counter < auth_hmac_md5_len(o.eigrp.auth) ; counter++)
				*checksum++ = __8BIT_RND(0);
			/* Computing the Checksum offset. */
			offset += EIGRP_TLEN_AUTH;
		}
	}

	/*
	 * AFAIK,   there are differences when building the EIGRP packet for
	 * Update, Request, Query and Reply.  Any EIGRP PCAP file I saw does
	 * not carry Paremeter,  Software Version and/or Multicast Sequence,
	 * instead, it carries Authentication Data, IP Internal and External
	 * Routes or nothing (depends on the EIGRP Type).
	 */
	if(o.eigrp.opcode == EIGRP_OPCODE_UPDATE   ||
	   o.eigrp.opcode == EIGRP_OPCODE_REQUEST  ||
	   o.eigrp.opcode == EIGRP_OPCODE_QUERY    ||
	   o.eigrp.opcode == EIGRP_OPCODE_REPLY){
		if(o.eigrp.type == EIGRP_TYPE_INTERNAL ||
		   o.eigrp.type == EIGRP_TYPE_EXTERNAL){
			/*
			 * Enhanced Interior Gateway Routing Protocol (EIGRP)
			 *
			 * IP Internal Routes TLV  (EIGRP Type = 0x0102)
			 *
			 *    0                   1                   2                   3 3
			 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *   |             Type              |            Length             |
			 *   +---------------------------------------------------------------+
			 *   |                       Next Hop Address                        |
			 *   +---------------------------------------------------------------+
			 *   |                             Delay                             |
			 *   +---------------------------------------------------------------+
			 *   |                           Bandwidth                           |
			 *   +---------------------------------------------------------------+
			 *   |        Maximum Transmission Unit (MTU)        |   Hop Count   |
			 *   +---------------------------------------------------------------+
			 *   |  Reliability  |     Load      |           Reserved            |
			 *   +---------------------------------------------------------------+
			 *   |    Prefix     //
			 *   +---------------+
			 *
			 *   +---------------------------------------------------------------+
			 *   //           Destination IP Address(es) (1-4 octets)            |
			 *   +---------------------------------------------------------------+
			 *
			 * IP External Routes TLV  (EIGRP Type = 0x0103)
			 *
			 *    0                   1                   2                   3 3
			 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *   |             Type              |            Length             |
			 *   +---------------------------------------------------------------+
			 *   |                       Next Hop Address                        |
			 *   +---------------------------------------------------------------+
			 *   |                      Originating Router                       |
			 *   +---------------------------------------------------------------+
			 *   |                Originating Autonomous System                  |
			 *   +---------------------------------------------------------------+
			 *   |                         Arbitrary TAG                         |
			 *   +---------------------------------------------------------------+
			 *   |                   External Protocol Metric                    |
			 *   +---------------------------------------------------------------+
			 *   |           Reserved1           | Ext. Proto ID |     Flags     |
			 *   +---------------------------------------------------------------+
			 *   |                             Delay                             |
			 *   +---------------------------------------------------------------+
			 *   |                           Bandwidth                           |
			 *   +---------------------------------------------------------------+
			 *   |        Maximum Transmission Unit (MTU)        |   Hop Count   |
			 *   +---------------------------------------------------------------+
			 *   |  Reliability  |     Load      |           Reserved2           |
			 *   +---------------------------------------------------------------+
			 *   |    Prefix     //
			 *   +---------------+
			 *
			 *   +---------------------------------------------------------------+
			 *   //           Destination IP Address(es) (1-4 octets)            |
			 *   +---------------------------------------------------------------+
			 *
			 * The only difference between Internal and External Routes TLVs is 20
			 * octets.
			 */
			*((u_int16_t *)checksum) = htons(o.eigrp.type == EIGRP_TYPE_INTERNAL ? \
				                           EIGRP_TYPE_INTERNAL : \
			                           EIGRP_TYPE_EXTERNAL);
			checksum += sizeof(u_int16_t);
			/*
			 * For both Internal and External Routes TLV the code must perform
			 * an additional step to compute the EIGRP header length,  because 
			 * it depends on the the EIGRP Prefix, and it can be 1-4 octets.
			 */
			*((u_int16_t *)checksum) = htons(o.eigrp.length ? \
				                           o.eigrp.length : \
			                           (o.eigrp.type == EIGRP_TYPE_INTERNAL ? \
				                           EIGRP_TLEN_INTERNAL : \
			                           EIGRP_TLEN_EXTERNAL) + \
			                           EIGRP_DADDR_LENGTH(prefix));
			checksum += sizeof(u_int16_t);
			*((in_addr_t *)checksum) = INADDR_RND(o.eigrp.next_hop);
			checksum += sizeof(in_addr_t);
			/*
 			 * The only difference between Internal and External Routes TLVs is 20
			 * octets. Building 20 extra octets for IP External Routes TLV.
			 */
			if(o.eigrp.type == EIGRP_TYPE_EXTERNAL){
				*((in_addr_t *)checksum) = INADDR_RND(o.eigrp.src_router);
				checksum += sizeof(in_addr_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.eigrp.src_as));
				checksum += sizeof(u_int32_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.eigrp.tag));
				checksum += sizeof(u_int32_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.eigrp.proto_metric));
				checksum += sizeof(u_int32_t);
				*((u_int16_t *)checksum) = o.eigrp.opcode == EIGRP_OPCODE_UPDATE ? \
					                           FIELD_MUST_BE_ZERO : \
				                           htons(0x0004);
				checksum += sizeof(u_int16_t);
				*checksum++ = __8BIT_RND(o.eigrp.proto_id);
				*checksum++ = __8BIT_RND(o.eigrp.ext_flags);
			}
			*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.eigrp.delay));
			checksum += sizeof(u_int32_t);
			*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.eigrp.bandwidth));
			checksum += sizeof(u_int32_t);
			*((u_int32_t *)checksum) = htonl(__24BIT_RND(o.eigrp.mtu) << 8);
			checksum += sizeof(u_int32_t) - 1;
			*checksum++ = __8BIT_RND(o.eigrp.hop_count);
			*checksum++ = __8BIT_RND(o.eigrp.reliability);
			*checksum++ = __8BIT_RND(o.eigrp.load);
			*((u_int16_t *)checksum) = o.eigrp.opcode == EIGRP_OPCODE_UPDATE ? \
				                           FIELD_MUST_BE_ZERO : \
			                           htons(0x0004);
			checksum += sizeof(u_int16_t);
			*checksum++ = prefix;
			*((in_addr_t *)checksum) = EIGRP_DADDR_BUILD(dest, prefix);
			checksum += EIGRP_DADDR_LENGTH(prefix);
			/* Computing the Checksum offset. */
			offset += (o.eigrp.type == EIGRP_TYPE_INTERNAL ? \
				          EIGRP_TLEN_INTERNAL : \
			          EIGRP_TLEN_EXTERNAL) + \
			          EIGRP_DADDR_LENGTH(prefix);
		}
	/*
	 * In the other hand,   EIGRP Packet for Hello can carry Paremeter, 
	 * Software Version, Multicast Sequence or nothing (Acknowledge).
	 */
	}else if(o.eigrp.opcode == EIGRP_OPCODE_HELLO){
		/*
		 * AFAIK,  EIGRP TLVs must follow a predefined sequence in order to
		 * be built. I am not sure whether any TLV's precedence will impact
		 * in the routers'  processing of  EIGRP Packet,  so I am following 
		 * exactly what I saw on live  EIGRP PCAP files.  Read the code and
		 * you will understand what I am talking about.
		 */
		switch(o.eigrp.type){
			case EIGRP_TYPE_PARAMETER:
				/*
				 * Enhanced Interior Gateway Routing Protocol (EIGRP)
				 *
				 * General Parameter TLV (EIGRP Type = 0x0001)
				 *
				 *    0                   1                   2                   3 3
				 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *   |             Type              |            Length             |
				 *   +---------------------------------------------------------------+
				 *   |      K1       |      K2       |      K3       |      K4       |
				 *   +---------------------------------------------------------------+
				 *   |      K5       |    Reserved   |           Hold Time           |
				 *   +---------------------------------------------------------------+
				 */
eigrp_parameter:		*((u_int16_t *)checksum) = htons(EIGRP_TYPE_PARAMETER);
				checksum += sizeof(u_int16_t);
				*((u_int16_t *)checksum) = htons(o.eigrp.length ? \
					                           o.eigrp.length : \
				                           EIGRP_TLEN_PARAMETER);
				checksum += sizeof(u_int16_t);
				*checksum++ = (o.eigrp.values & EIGRP_KVALUE_K1) == EIGRP_KVALUE_K1 ? \
					              __8BIT_RND(o.eigrp.k1) : \
				              o.eigrp.k1;
				*checksum++ = (o.eigrp.values & EIGRP_KVALUE_K2) == EIGRP_KVALUE_K2 ? \
					              __8BIT_RND(o.eigrp.k2) : \
				              o.eigrp.k2;
				*checksum++ = (o.eigrp.values & EIGRP_KVALUE_K3) == EIGRP_KVALUE_K3 ? \
					              __8BIT_RND(o.eigrp.k3) : \
				              o.eigrp.k3;
				*checksum++ = (o.eigrp.values & EIGRP_KVALUE_K4) == EIGRP_KVALUE_K4 ? \
					              __8BIT_RND(o.eigrp.k4) : \
				              o.eigrp.k4;
				*checksum++ = (o.eigrp.values & EIGRP_KVALUE_K5) == EIGRP_KVALUE_K5 ? \
					              __8BIT_RND(o.eigrp.k5) : \
				              o.eigrp.k5;
				*checksum++ = FIELD_MUST_BE_ZERO;
				*((u_int16_t *)checksum) = htons(o.eigrp.hold);
				checksum += sizeof(u_int16_t);
				/* Computing the Checksum offset. */
				offset += EIGRP_TLEN_PARAMETER;
				/* Going to the next TLV, if it needs to do so. */
				if(o.eigrp.type == EIGRP_TYPE_SOFTWARE ||
				   o.eigrp.type == EIGRP_TYPE_MULTICAST)
					goto eigrp_software;
				break;
			case EIGRP_TYPE_SOFTWARE:
				/* Going to the next TLV. */
				goto eigrp_parameter;
				/*
				 * Enhanced Interior Gateway Routing Protocol (EIGRP)
				 *
				 * Software Version TLV (EIGRP Type = 0x0004)
				 *
				 *    0                   1                   2                   3 3
				 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *   |             Type              |            Length             |
				 *   +---------------------------------------------------------------+
				 *   |   IOS Major   |   IOS Minor   |  EIGRP Major  |  EIGRP Minor  |
				 *   +---------------------------------------------------------------+
				 */
eigrp_software:			*((u_int16_t *)checksum) = htons(EIGRP_TYPE_SOFTWARE);
				checksum += sizeof(u_int16_t);
				*((u_int16_t *)checksum) = htons(o.eigrp.length ? \
					                           o.eigrp.length : \
				                           EIGRP_TLEN_SOFTWARE);
				checksum += sizeof(u_int16_t);
				*checksum++ = __8BIT_RND(o.eigrp.ios_major);
				*checksum++ = __8BIT_RND(o.eigrp.ios_minor);
				*checksum++ = __8BIT_RND(o.eigrp.ver_major);
				*checksum++ = __8BIT_RND(o.eigrp.ver_minor);
				/* Computing the Checksum offset. */
				offset += EIGRP_TLEN_SOFTWARE;
				/* Going to the next TLV, if it needs to do so. */
				if(o.eigrp.type == EIGRP_TYPE_MULTICAST)
					goto eigrp_multicast;
				break;
			case EIGRP_TYPE_MULTICAST:
				/* Going to the next TLV. */
				goto eigrp_parameter;
				/*
				 * Enhanced Interior Gateway Routing Protocol (EIGRP)
				 *
				 * Sequence TLV (EIGRP Type = 0x0003)
				 *
				 *    0                   1                   2                   3 3
				 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *   |             Type              |            Length             |
				 *   +---------------------------------------------------------------+
				 *   |  Addr Length  //
				 *   +---------------+
				 *
				 *   +---------------------------------------------------------------+
				 *   //                         IP Address                           |
				 *   +---------------------------------------------------------------+
				 */
eigrp_multicast:		*((u_int16_t *)checksum) = htons(EIGRP_TYPE_SEQUENCE);
				checksum += sizeof(u_int16_t);
				*((u_int16_t *)checksum) = htons(o.eigrp.length ? \
					                           o.eigrp.length : \
				                           EIGRP_TLEN_SEQUENCE);
				checksum += sizeof(u_int16_t);
				*checksum++ = sizeof(o.eigrp.address);
				*((in_addr_t *)checksum) = INADDR_RND(o.eigrp.address);
				checksum += sizeof(in_addr_t);
				/*
				 * Enhanced Interior Gateway Routing Protocol (EIGRP)
				 *
				 * Next Multicast Sequence TLV (EIGRP Type = 0x0005)
				 *
				 *    0                   1                   2                   3 3
				 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *   |             Type              |            Length             |
				 *   +---------------------------------------------------------------+
				 *   |                    Next Multicast Sequence                    |
				 *   +---------------------------------------------------------------+
				 */				
				*((u_int16_t *)checksum) = htons(EIGRP_TYPE_MULTICAST);
				checksum += sizeof(u_int16_t);
				*((u_int16_t *)checksum) = htons(o.eigrp.length ? \
					                           o.eigrp.length : \
				                           EIGRP_TLEN_MULTICAST);
				checksum += sizeof(u_int16_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.eigrp.multicast));
				checksum += sizeof(u_int32_t);
				/* Computing the Checksum offset. */
				offset += EIGRP_TLEN_MULTICAST + \
				          EIGRP_TLEN_SEQUENCE;
				break;
			default:
				break;
		}
	}

	/* Computing the checksum. */
	eigrp->check    = o.bogus_csum ? \
		                  __16BIT_RND(0) : \
	                  cksum((u_int16_t *)eigrp, offset);

	/* GRE Encapsulation takes place. */
	if(o.encapsulated){
		/* Computing the checksum. */
		if((o.gre.options & GRE_OPTION_CHECKSUM) == GRE_OPTION_CHECKSUM)
			gre_sum->check  = o.bogus_csum ? \
					          __16BIT_RND(0) : \
				          cksum((u_int16_t *)gre, packet_size - sizeof(struct iphdr));
	}

	/* Sending packet. */
	if(sendto(fd, &packet, packet_size, 0|MSG_NOSIGNAL, (struct sockaddr *) &sin, sizeof(struct sockaddr)) == -1 && errno != EPERM){
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
#endif  /* EIGRP_C__ */
