/* 
 * $Id: dccp.c,v 5.26 2011-03-11 11:17:27-03 nbrito Exp $
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
#ifndef DCCP_C__
#define DCCP_C__ 1

#include <common.h>


/*
 * External prototypes.
 */
extern inline size_t gre_opt_len(const u_int8_t, const u_int8_t);


/* 
 * Local Global Variables.
 */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 5.26 $";
#endif  /* __HAVE_DEBUG__ */


/* Function Name: DCCP packet header configuration.

   Description:   This function configures and sends the DCCP packet header.

   Targets:       N/A */
inline const void * dccp(const socket_t fd, const struct config_options o){
	/* GRE options size. */
	size_t greoptlen = gre_opt_len(o.gre.options, o.encapsulated);
	/* DCCP Header length. */
	size_t dccp_length = dccp_packet_hdr_len(o.dccp.type);
	/* DCCP Extended Sequence NUmber length. */
	u_int32_t dccp_ext_length = (o.dccp.ext ? \
		                            sizeof(struct dccp_hdr_ext) : \
	                            0);
	/* Packet size. */
	const u_int32_t packet_size = sizeof(struct iphdr)    + \
	                              greoptlen               + \
	                              sizeof(struct dccp_hdr) + \
	                              dccp_ext_length         + \
	                              dccp_length;
	/* Checksum offset and GRE offset. */
	static u_int32_t offset = 0, greoffset =  0;
	/* Packet and Checksum. */
	u_int8_t packet[packet_size], * checksum = NULL;
	/* Socket address and IP heade. */
	static struct sockaddr_in sin;
	static struct iphdr * ip;
	/* GRE header, GRE Checksum header and GRE Encapsulated IP Header. */
	static struct gre_hdr * gre;
	static struct gre_sum_hdr * gre_sum;
	static struct gre_key_hdr * gre_key;
	static struct gre_seq_hdr * gre_seq;
	static struct iphdr * gre_ip;
	/* DCCP header and PSEUDO header. */
	static struct dccp_hdr * dccp;
	static struct psdhdr * pseudo;
	/* DCCP Headers. */
	static struct dccp_hdr_ext * dccp_ext;
	static struct dccp_hdr_request * dccp_req;
	static struct dccp_hdr_response * dccp_res;
	static struct dccp_hdr_ack_bits * dccp_ack;
	static struct dccp_hdr_reset * dccp_rst;

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
		gre->C       = o.gre.C;
		gre->K       = o.gre.K;
		gre->R       = FIELD_MUST_BE_ZERO;
		gre->S       = o.gre.S;
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
	                           sizeof(struct dccp_hdr) + \
	                           dccp_ext_length         + \
	                           dccp_length);
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

	/* DCCP Header structure making a pointer to Packet. */
	dccp                 = (struct dccp_hdr *)((u_int8_t *)ip + sizeof(struct iphdr) + greoptlen);
	dccp->dccph_sport    = htons(IPPORT_RND(o.source)); 
	dccp->dccph_dport    = htons(IPPORT_RND(o.dest));
	/*
	 * Datagram Congestion Control Protocol (DCCP) (RFC 4340)
	 *
	 *   Data Offset: 8 bits
	 *     The offset from the start of the packet's DCCP header to the start
	 *     of its  application data area, in 32-bit words.  The receiver MUST
	 *     ignore packets whose Data Offset is smaller than the minimum-sized
	 *     header for the given Type or larger than the DCCP packet itself.
	 */
	dccp->dccph_doff     = o.dccp.doff ? \
		                       o.dccp.doff : \
	                       (sizeof(struct dccp_hdr) + \
	                       dccp_length + \
	                       dccp_ext_length)/4;
	dccp->dccph_type     = o.dccp.type;
	dccp->dccph_ccval    = __4BIT_RND(o.dccp.ccval);
	/*
	 * Datagram Congestion Control Protocol (DCCP) (RFC 4340)
	 *
	 * 9.2.  Header Checksum Coverage Field
	 *
	 *   The  Checksum Coverage field in the DCCP generic header (see Section
	 *   5.1)  specifies what parts of the packet are covered by the Checksum
	 *   field, as follows:
	 *
	 *   CsCov = 0      The  Checksum  field  covers  the  DCCP  header, DCCP
	 *                  options,    network-layer   pseudoheader,   and   all
	 *                  application  data  in the packet,  possibly padded on 
	 *                  the right with zeros to an even number of bytes.
	 *
	 *   CsCov = 1-15   The  Checksum  field  covers  the  DCCP  header, DCCP
	 *                  options,  network-layer pseudoheader, and the initial
	 *                  (CsCov-1)*4 bytes of the packet's application data.
	 */
	dccp->dccph_cscov    = o.dccp.cscov ? \
		                       (o.dccp.cscov-1)*4 : \
	                       (o.bogus_csum ? \
		                       __4BIT_RND(0) : \
	                       o.dccp.cscov);
	/*
	 * Datagram Congestion Control Protocol (DCCP) (RFC 4340)
	 *
	 * 5.1.  Generic Header
	 *
	 *   The DCCP generic header takes different forms depending on the value
	 *   of X,  the Extended Sequence Numbers bit.  If X is one, the Sequence
	 *   Number field is 48 bits long, and the generic header takes 16 bytes,
	 *   as follows.
	 *
	 *        0                   1                   2                   3
	 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *       |          Source Port          |           Dest Port           |
	 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *       |  Data Offset  | CCVal | CsCov |           Checksum            |
	 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *       |     |       |X|               |                               .
	 *       | Res | Type  |=|   Reserved    |  Sequence Number (high bits)  .
	 *       |     |       |1|               |                               .
	 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *       .                  Sequence Number (low bits)                   |
	 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 *   If  X  is  zero,  only the low 24 bits of the  Sequence  Number  are
	 *   transmitted, and the generic header is 12 bytes long.
	 *
	 *        0                   1                   2                   3
	 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *       |          Source Port          |           Dest Port           |
	 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *       |  Data Offset  | CCVal | CsCov |           Checksum            |
	 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	 *       |     |       |X|                                               |
	 *       | Res | Type  |=|          Sequence Number (low bits)           |
	 *       |     |       |0|                                               |
	 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	dccp->dccph_x        = o.dccp.ext;
	dccp->dccph_seq      = htons(__16BIT_RND(o.dccp.sequence_01));
	dccp->dccph_seq2     = o.dccp.ext ? \
		                       0 : \
	                       __8BIT_RND(o.dccp.sequence_02);
	dccp->dccph_checksum = 0;
	/* Computing the Checksum offset. */
	offset  = sizeof(struct dccp_hdr);

	/* Storing both Checksum and Packet. */
	checksum = (u_int8_t *)dccp + offset;

	/* DCCP Extended Header structure making a pointer to Checksum. */
	if(o.dccp.ext){
		dccp_ext                = (struct dccp_hdr_ext *)(checksum + (offset - sizeof(struct dccp_hdr)));
		dccp_ext->dccph_seq_low = htonl(__32BIT_RND(o.dccp.sequence_03));
		/* Computing the Checksum offset. */
		offset += sizeof(struct dccp_hdr_ext);
	}

	/* Identifying the DCCP Type and building it. */
	switch(o.dccp.type){
		case DCCP_PKT_REQUEST:
			/* DCCP Request Header structure making a pointer to Checksum. */
			dccp_req                    = (struct dccp_hdr_request *)(checksum + (offset - sizeof(struct dccp_hdr)));
			dccp_req->dccph_req_service = htonl(__32BIT_RND(o.dccp.service));
			/* Computing the Checksum offset. */
			offset += sizeof(struct dccp_hdr_request);
			break;
		case DCCP_PKT_RESPONSE:
			/* DCCP Response Header structure making a pointer to Checksum. */
			dccp_res                                   = (struct dccp_hdr_response *)(checksum + (offset - sizeof(struct dccp_hdr)));
			dccp_res->dccph_resp_ack.dccph_reserved1   = FIELD_MUST_BE_ZERO;
			dccp_res->dccph_resp_ack.dccph_ack_nr_high = htons(__16BIT_RND(o.dccp.acknowledge_01));
			dccp_res->dccph_resp_ack.dccph_ack_nr_low  = htonl(__32BIT_RND(o.dccp.acknowledge_02));
			dccp_res->dccph_resp_service               = htonl(__32BIT_RND(o.dccp.service));
			/* Computing the Checksum offset. */
			offset += sizeof(struct dccp_hdr_response);
			break;
		case DCCP_PKT_DATA:
			break;
		case DCCP_PKT_DATAACK:
		case DCCP_PKT_ACK:
		case DCCP_PKT_SYNC:
		case DCCP_PKT_SYNCACK:
		case DCCP_PKT_CLOSE:
		case DCCP_PKT_CLOSEREQ:
			/* DCCP Acknowledgment Header structure making a pointer to Checksum. */
			dccp_ack                    = (struct dccp_hdr_ack_bits *)(checksum + (offset - sizeof(struct dccp_hdr)));
			dccp_ack->dccph_reserved1   = FIELD_MUST_BE_ZERO;
			dccp_ack->dccph_ack_nr_high = htons(__16BIT_RND(o.dccp.acknowledge_01));
			/* Until DCCP Options implementation. */
			if(o.dccp.type == DCCP_PKT_DATAACK ||
			   o.dccp.type == DCCP_PKT_ACK)
				dccp_ack->dccph_ack_nr_low  = htonl(0x00000001);
			else
				dccp_ack->dccph_ack_nr_low  = htonl(__32BIT_RND(o.dccp.acknowledge_02));
			/* Computing the Checksum offset. */
			offset += sizeof(struct dccp_hdr_ack_bits);
			break;
		default:
			/* DCCP Reset Header structure making a pointer to Checksum. */
			dccp_rst                                    = (struct dccp_hdr_reset *)(checksum + (offset - sizeof(struct dccp_hdr)));
			dccp_rst->dccph_reset_ack.dccph_reserved1   = FIELD_MUST_BE_ZERO;
			dccp_rst->dccph_reset_ack.dccph_ack_nr_high = htons(__16BIT_RND(o.dccp.acknowledge_01));
			dccp_rst->dccph_reset_ack.dccph_ack_nr_low  = htonl(__32BIT_RND(o.dccp.acknowledge_02));
			dccp_rst->dccph_reset_code                  = __8BIT_RND(o.dccp.rst_code);
			/* Computing the Checksum offset. */
			offset += sizeof(struct dccp_hdr_reset);
			break;
	}

	/* Checksum making a pointer to PSEUDO Header structure. */
	pseudo           = (struct psdhdr *)(checksum + (offset - sizeof(struct dccp_hdr)));
	pseudo->saddr    = o.encapsulated ? \
		                   gre_ip->saddr : \
	                   ip->saddr;
	pseudo->daddr    = o.encapsulated ? \
		                   gre_ip->daddr : \
	                   ip->daddr;
	pseudo->zero     = 0;
	pseudo->protocol = o.ip.protocol;
	pseudo->len      = htons(offset);
	/* Computing the Checksum offset. */
	offset += sizeof(struct psdhdr);

	/* Computing the checksum. */
	dccp->dccph_checksum = o.bogus_csum ? \
		                       __16BIT_RND(0) : \
	                       cksum((u_int16_t *)dccp, offset);

	/* GRE Encapsulation takes place. */
	if(o.encapsulated){
		/* Computing the checksum. */
		if((o.gre.options & GRE_OPTION_CHECKSUM) == GRE_OPTION_CHECKSUM)
			gre_sum->check  = o.bogus_csum ? \
					          __16BIT_RND(0) : \
				          cksum((u_int16_t *)gre, packet_size - sizeof(struct iphdr));
	}

	/* Sending Packet. */
	if(sendto(fd, &packet, packet_size, 0|MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM){
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
#endif  /* DCCP_C__ */
