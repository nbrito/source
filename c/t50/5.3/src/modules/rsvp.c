/* 
 * $Id: rsvp.c,v 5.25 2011-03-11 11:17:28-03 nbrito Exp $
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
#ifndef RSVP_C__
#define RSVP_C__ 1

#include <common.h>


/*
 * External prototypes.
 */
extern inline size_t rsvp_objects_len(const u_int8_t, const u_int8_t, const u_int8_t, const u_int8_t);
extern inline size_t gre_opt_len(const u_int8_t, const u_int8_t);


/* 
 * Local Global Variables.
 */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 5.25 $";
#endif  /* __HAVE_DEBUG__ */


/* Function Name: RSVP packet header configuration.

   Description:   This function configures and sends the RSVP packet header.

   Targets:       N/A */
inline const void * rsvp(const socket_t fd, const struct config_options o){
	/* GRE options size. */
	size_t greoptlen = gre_opt_len(o.gre.options, o.encapsulated);
	/* RSVP Objects Length. */
	size_t objects_length = rsvp_objects_len(o.rsvp.type, o.rsvp.scope, o.rsvp.adspec, o.rsvp.tspec);
	/* Packet size. */
	const u_int32_t packet_size = sizeof(struct iphdr)           + \
	                              sizeof(struct rsvp_common_hdr) + \
	                              greoptlen                      + \
	                              objects_length;
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
	/* RSVP Common header. */
	static struct rsvp_common_hdr * rsvp;

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
		gre_ip->tot_len  = htons(sizeof(struct iphdr)           + \
		                         sizeof(struct rsvp_common_hdr) +
		                   objects_length);
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

	/* RSVP Header structure making a pointer to IP Header structure. */
	rsvp           = (struct rsvp_common_hdr *)((u_int8_t *)ip + sizeof(struct iphdr) + greoptlen);
	rsvp->flags    = __4BIT_RND(o.rsvp.flags);
	rsvp->version  = RSVPVERSION;
	rsvp->type     = o.rsvp.type;
	rsvp->ttl      = __8BIT_RND(o.rsvp.ttl);
	rsvp->length   = htons(sizeof(struct rsvp_common_hdr) + \
	                 objects_length);
	rsvp->reserved = FIELD_MUST_BE_ZERO;
	rsvp->check    = 0;
	/* Computing the Checksum offset. */
	offset  = sizeof(struct rsvp_common_hdr);

	/* Storing both Checksum and Packet. */
	checksum = (u_int8_t *)rsvp + offset;

	/*
	 * The SESSION Object Class is present for all RSVP Messages.
	 *
	 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
	 *
	 * A.1 SESSION Class
	 *
	 * SESSION Class = 1.
	 *
	 * o    IPv4/UDP SESSION object: Class = 1, C-Type = 1
	 *
	 * +-------------+-------------+-------------+-------------+
	 * |             IPv4 DestAddress (4 bytes)                |
	 * +-------------+-------------+-------------+-------------+
	 * | Protocol Id |    Flags    |          DstPort          |
	 * +-------------+-------------+-------------+-------------+
	 */
	*((u_int16_t *)checksum) = htons(RSVP_LENGTH_SESSION);
	checksum += sizeof(u_int16_t);
	*checksum++ = RSVP_OBJECT_SESSION;
	*checksum++ = 1;
	*((in_addr_t *)checksum) = INADDR_RND(o.rsvp.session_addr);
	checksum += sizeof(in_addr_t);
	*checksum++ = __8BIT_RND(o.rsvp.session_proto);
	*checksum++ = __8BIT_RND(o.rsvp.session_flags);
	*((u_int16_t *)checksum) = htons(__16BIT_RND(o.rsvp.session_port));
	checksum += sizeof(u_int16_t);
	/* Computing the Checksum offset. */
	offset += RSVP_LENGTH_SESSION;
	
	/* 
	 * The RESV_HOP Object Class is present for the following:
	 * 3.1.3 Path Messages
	 * 3.1.4 Resv Messages
	 * 3.1.5 Path Teardown Messages
	 * 3.1.6 Resv Teardown Messages
	 * 3.1.8 Resv Error Messages
	 */
	if(o.rsvp.type == RSVP_MESSAGE_TYPE_PATH ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_RESV ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_PATHTEAR ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_RESVTEAR ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_RESVERR){
		/*
		 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
		 *
		 * A.2 RSVP_HOP Class
		 *
		 * RSVP_HOP class = 3.
		 *
		 * o    IPv4 RSVP_HOP object: Class = 3, C-Type = 1
		 *
		 * +-------------+-------------+-------------+-------------+
		 * |             IPv4 Next/Previous Hop Address            |
		 * +-------------+-------------+-------------+-------------+
		 * |                 Logical Interface Handle              |
		 * +-------------+-------------+-------------+-------------+
		 */
		*((u_int16_t *)checksum) = htons(RSVP_LENGTH_RESV_HOP);
		checksum += sizeof(u_int16_t);
		*checksum++ = RSVP_OBJECT_RESV_HOP;
		*checksum++ = 1;
		*((in_addr_t *)checksum) = INADDR_RND(o.rsvp.hop_addr);
		checksum += sizeof(in_addr_t);
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.hop_iface));
		checksum += sizeof(u_int32_t);
		/* Computing the Checksum offset. */
		offset += RSVP_LENGTH_RESV_HOP;
	}

	/* 
	 * The TIME_VALUES Object Class is present for the following:
	 * 3.1.3 Path Messages
	 * 3.1.4 Resv Messages
	 */
	if(o.rsvp.type == RSVP_MESSAGE_TYPE_PATH ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_RESV){
		/*
		 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
		 *
		 * A.4 TIME_VALUES Class
		 *
		 * TIME_VALUES class = 5.
		 *
		 * o    TIME_VALUES Object: Class = 5, C-Type = 1
		 *
		 * +-------------+-------------+-------------+-------------+
		 * |                   Refresh Period R                    |
		 * +-------------+-------------+-------------+-------------+
		 */
		*((u_int16_t *)checksum) = htons(RSVP_LENGTH_TIME_VALUES);
		checksum += sizeof(u_int16_t);
		*checksum++ = RSVP_OBJECT_TIME_VALUES;
		*checksum++ = 1;
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.time_refresh));
		checksum += sizeof(u_int32_t);
		/* Computing the Checksum offset. */
		offset += RSVP_LENGTH_TIME_VALUES;
	}

	/* 
	 * The ERROR_SPEC Object Class is present for the following:
	 * 3.1.5 Path Teardown Messages
	 * 3.1.8 Resv Error Messages
	 * 3.1.9 Confirmation Messages
	 */
	if(o.rsvp.type == RSVP_MESSAGE_TYPE_PATHERR ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_RESVERR ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_RESVCONF){
		/*
		 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
		 *
		 * A.5 ERROR_SPEC Class
		 *
		 * ERROR_SPEC class = 6.
		 *
		 * o    IPv4 ERROR_SPEC object: Class = 6, C-Type = 1
		 *
		 * +-------------+-------------+-------------+-------------+
		 * |            IPv4 Error Node Address (4 bytes)          |
		 * +-------------+-------------+-------------+-------------+
		 * |    Flags    |  Error Code |        Error Value        |
		 * +-------------+-------------+-------------+-------------+
		 */
		*((u_int16_t *)checksum) = htons(RSVP_LENGTH_ERROR_SPEC);
		checksum += sizeof(u_int16_t);
		*checksum++ = RSVP_OBJECT_ERROR_SPEC;
		*checksum++ = 1;
		*((in_addr_t *)checksum) = INADDR_RND(o.rsvp.error_addr);
		checksum += sizeof(in_addr_t);
		*checksum++ = __3BIT_RND(o.rsvp.error_flags);
		*checksum++ = __8BIT_RND(o.rsvp.error_code);
		*((u_int16_t *)checksum) = htons(__16BIT_RND(o.rsvp.error_value));
		checksum += sizeof(u_int16_t);
		/* Computing the Checksum offset. */
		offset += RSVP_LENGTH_ERROR_SPEC;
	}

	/* 
	 * The SENDER_TEMPLATE,  SENDER_TSPEC and  ADSPEC Object Classes are
	 * present for the following:
	 * 3.1.3 Path Messages
	 * 3.1.5 Path Teardown Messages
	 * 3.1.7 Path Error Messages
	 */
	if(o.rsvp.type == RSVP_MESSAGE_TYPE_PATH     ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_PATHTEAR ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_PATHERR){
		/*
		 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
		 *
		 * A.10 SENDER_TEMPLATE Class
		 *
		 * SENDER_TEMPLATE class = 11.
		 *
		 * o    IPv4 SENDER_TEMPLATE object: Class = 11, C-Type = 1
		 *
		 * Definition same as IPv4/UDP FILTER_SPEC object.
		 *
		 * RSVP Extensions for IPSEC (RFC 2207)
		 *
		 * 3.3  SENDER_TEMPLATE Class
		 *
		 * SENDER_TEMPLATE class = 11.
		 *
		 * o    IPv4/GPI SENDER_TEMPLATE object: Class = 11, C-Type = 4
		 *
		 * Definition same as IPv4/GPI FILTER_SPEC object.
		 */
		*((u_int16_t *)checksum) = htons(RSVP_LENGTH_SENDER_TEMPLATE);
		checksum += sizeof(u_int16_t);
		*checksum++ = RSVP_OBJECT_SENDER_TEMPLATE;
		*checksum++ = 1;
		*((in_addr_t *)checksum) = INADDR_RND(o.rsvp.sender_addr);
		checksum += sizeof(in_addr_t);
		*((u_int16_t *)checksum) = FIELD_MUST_BE_ZERO;
		checksum += sizeof(u_int16_t);
		*((u_int16_t *)checksum) = htons(__16BIT_RND(o.rsvp.sender_port));
		checksum += sizeof(u_int16_t);
		/* Computing the Checksum offset. */
		offset += RSVP_LENGTH_SENDER_TEMPLATE;
		/*
		 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
		 *
		 * A.11 SENDER_TSPEC Class
		 *
		 * SENDER_TSPEC class = 12.
		 *
		 * o    Intserv SENDER_TSPEC object: Class = 12, C-Type = 2
		 *
		 * The contents and encoding rules for this object are specified
		 * in documents prepared by the int-serv working group.
		 */
		*((u_int16_t *)checksum) = htons(RSVP_LENGTH_SENDER_TSPEC + \
		                           TSPEC_SERVICES(o.rsvp.tspec));
		checksum += sizeof(u_int16_t);
		*checksum++ = RSVP_OBJECT_SENDER_TSPEC;
		*checksum++ = 2;
		/*
		 * The Use of RSVP with IETF Integrated Services (RFC 2210)
		 *
		 * 3.1. RSVP SENDER_TSPEC Object
		 *
		 *       31           24 23           16 15            8 7             0
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 1   | 0 (a) |    reserved           |             7 (b)             |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 2   |    1  (c)     |0| reserved    |             6 (d)             |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 3   |   127 (e)     |    0 (f)      |             5 (g)             |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 4   |  Token Bucket Rate [r] (32-bit IEEE floating point number)    |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 5   |  Token Bucket Size [b] (32-bit IEEE floating point number)    |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 6   |  Peak Data Rate [p] (32-bit IEEE floating point number)       |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 7   |  Minimum Policed Unit [m] (32-bit integer)                    |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 8   |  Maximum Packet Size [M]  (32-bit integer)                    |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		*((u_int16_t *)checksum) = FIELD_MUST_BE_ZERO;
		checksum += sizeof(u_int16_t);
		*((u_int16_t *)checksum) = htons((TSPEC_SERVICES(o.rsvp.tspec) - \
		                           RSVP_LENGTH_SENDER_TSPEC)/4);
		checksum += sizeof(u_int16_t);
		*checksum++ = o.rsvp.tspec;
		*checksum++ = FIELD_MUST_BE_ZERO;
		*((u_int16_t *)checksum) = htons(TSPEC_SERVICES(o.rsvp.tspec)/4);
		checksum += sizeof(u_int16_t);

		/* Identifying the RSVP TSPEC and building it. */
		switch(o.rsvp.tspec){
			case TSPEC_TRAFFIC_SERVICE:
			case TSPEC_GUARANTEED_SERVICE:
				*checksum++ = TSPECT_TOKEN_BUCKET_SERVICE;
				*checksum++ = FIELD_MUST_BE_ZERO;
				*((u_int16_t *)checksum) = htons((TSPEC_SERVICES(o.rsvp.tspec) - \
				                           TSPEC_MESSAGE_HEADER)/4);
				checksum += sizeof(u_int16_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.tspec_r));
				checksum += sizeof(u_int32_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.tspec_b));
				checksum += sizeof(u_int32_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.tspec_p));
				checksum += sizeof(u_int32_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.tspec_m));
				checksum += sizeof(u_int32_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.tspec_M));
				checksum += sizeof(u_int32_t);
				break;
			default:
				break;
		}
		/* Computing the Checksum offset. */
		offset += RSVP_LENGTH_SENDER_TSPEC;
		offset += TSPEC_SERVICES(o.rsvp.tspec);

		/*
		 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
		 *
		 * A.12 ADSPEC Class
		 *
		 * ADSPEC class = 13.
		 *
		 * o    Intserv ADSPEC object: Class = 13, C-Type = 2
		 *
		 * The contents and format for this object are specified in
		 * documents prepared by the int-serv working group.
		 */
		*((u_int16_t *)checksum) = htons(RSVP_LENGTH_ADSPEC + \
		                           ADSPEC_SERVICES(o.rsvp.adspec));
		checksum += sizeof(u_int16_t);
		*checksum++ = RSVP_OBJECT_ADSPEC;
		*checksum++ = 2;
		/*
		 * The Use of RSVP with IETF Integrated Services (RFC 2210)
		 *
		 * 3.3.1. RSVP ADSPEC format
		 *
		 *      31           24 23            16 15            8 7             0
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *     | 0 (a) |      reserved         |  Msg length - 1 (b)           |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *     |                                                               |
		 *     |    Default General Parameters fragment (Service 1)  (c)       |
		 *     |    (Always Present)                                           |
		 *     |                                                               |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *     |                                                               |
		 *     |    Guaranteed Service Fragment (Service 2)    (d)             |
		 *     |    (Present if application might use Guaranteed Service)      |
		 *     |                                                               |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *     |                                                               |
		 *     |    Controlled-Load Service Fragment (Service 5)  (e)          |
		 *     |    (Present if application might use Controlled-Load Service) |
		 *     |                                                               |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		*((u_int16_t *)checksum) = FIELD_MUST_BE_ZERO;
		checksum += sizeof(u_int16_t);

		*((u_int16_t *)checksum) = htons((ADSPEC_SERVICES(o.rsvp.adspec) - \
		                           ADSPEC_MESSAGE_HEADER)/4);
		checksum += sizeof(u_int16_t);
		/* Computing the Checksum offset. */
		offset += RSVP_LENGTH_ADSPEC;
		/*
		 * The Use of RSVP with IETF Integrated Services (RFC 2210)
		 *
		 * 3.3.2. Default General Characterization Parameters ADSPEC data fragment
		 *
		 *      31            24 23           16 15            8 7             0
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 1   |    1  (c)     |x| reserved    |           8 (d)               |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 2   |    4 (e)      |    (f)        |           1 (g)               |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 3   |        IS hop cnt (32-bit unsigned integer)                   |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 4   |    6 (h)      |    (i)        |           1 (j)               |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 5   |  Path b/w estimate  (32-bit IEEE floating point number)       |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 6   |     8 (k)     |    (l)        |           1 (m)               |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 7   |        Minimum path latency (32-bit integer)                  |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 8   |     10 (n)    |      (o)      |           1 (p)               |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * 9   |      Composed MTU (32-bit unsigned integer)                   |
		 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		*checksum++ = ADSPEC_PARAMETER_SERVICE;
		*checksum++ = FIELD_MUST_BE_ZERO;
		*((u_int16_t *)checksum) = htons((ADSPEC_PARAMETER_LENGTH - \
		                           ADSPEC_MESSAGE_HEADER)/4);
		checksum += sizeof(u_int16_t);
		*checksum++ = ADSPEC_PARAMETER_ISHOPCNT;
		*checksum++ = FIELD_MUST_BE_ZERO;
		*((u_int16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
		checksum += sizeof(u_int16_t);
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.adspec_hop));
		checksum += sizeof(u_int32_t);
		*checksum++ = ADSPEC_PARAMETER_BANDWIDTH;
		*checksum++ = FIELD_MUST_BE_ZERO;
		*((u_int16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
		checksum += sizeof(u_int16_t);
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.adspec_path));
		checksum += sizeof(u_int32_t);
		*checksum++ = ADSPEC_PARAMETER_LATENCY;
		*checksum++ = FIELD_MUST_BE_ZERO;
		*((u_int16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
		checksum += sizeof(u_int16_t);
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.adspec_minimum));
		checksum += sizeof(u_int32_t);
		*checksum++ = ADSPEC_PARAMETER_COMPMTU;
		*checksum++ = FIELD_MUST_BE_ZERO;
		*((u_int16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
		checksum += sizeof(u_int16_t);
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.adspec_mtu));
		checksum += sizeof(u_int32_t);
		/* Computing the Checksum offset. */
		offset += ADSPEC_PARAMETER_LENGTH;

		/* Identifying the ADSPEC and building it. */
		switch(o.rsvp.adspec){
			case ADSPEC_GUARANTEED_SERVICE:
				/*
				 * The Use of RSVP with IETF Integrated Services (RFC 2210)
				 *
				 * 3.3.3. Guaranteed Service ADSPEC data fragment
				 *
				 *      31            24 23           16 15            8 7             0
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 1   |     2 (a)     |x|  reserved   |             N-1 (b)           |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 2   |    133 (c)    |     0 (d)     |             1 (e)             |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 3   |   End-to-end composed value for C [Ctot] (32-bit integer)     |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 4   |     134 (f)   |       (g)     |             1 (h)             |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 5   |   End-to-end composed value for D [Dtot] (32-bit integer)     |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 6   |     135 (i)   |       (j)     |             1 (k)             |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 7   | Since-last-reshaping point composed C [Csum] (32-bit integer) |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 8   |     136 (l)   |       (m)     |             1 (n)             |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 9   | Since-last-reshaping point composed D [Dsum] (32-bit integer) |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 10  | Service-specific general parameter headers/values, if present |
				 *  .  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  .
				 * N   |                                                               |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 */
adspec_guarantee:		*checksum++ = ADSPEC_GUARANTEED_SERVICE;
				*checksum++ = FIELD_MUST_BE_ZERO;
				*((u_int16_t *)checksum) = htons((ADSPEC_GUARANTEED_LENGTH - \
				                           ADSPEC_MESSAGE_HEADER)/4);
				checksum += sizeof(u_int16_t);
				*checksum++ = 133;
				*checksum++ = FIELD_MUST_BE_ZERO;
				*((u_int16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
				checksum += sizeof(u_int16_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.adspec_Ctot));
				checksum += sizeof(u_int32_t);
				*checksum++ = 134;
				*checksum++ = FIELD_MUST_BE_ZERO;
				*((u_int16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
				checksum += sizeof(u_int16_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.adspec_Dtot));
				checksum += sizeof(u_int32_t);
				*checksum++ = 135;
				*checksum++ = FIELD_MUST_BE_ZERO;
				*((u_int16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
				checksum += sizeof(u_int16_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.adspec_Csum));
				checksum += sizeof(u_int32_t);
				*checksum++ = 136;
				*checksum++ = FIELD_MUST_BE_ZERO;
				*((u_int16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
				checksum += sizeof(u_int16_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.rsvp.adspec_Dsum));
				checksum += sizeof(u_int32_t);
				/* Computing the Checksum offset. */
				offset += ADSPEC_GUARANTEED_LENGTH;
				/* Going to the next ADSPEC, if it needs to do so. */
				if(o.rsvp.adspec == ADSPEC_CONTROLLED_SERVICE)
					goto adspec_controlled;
				break;
			case ADSPEC_CONTROLLED_SERVICE:
				/* Going to the next ADSPEC. */
				goto adspec_guarantee;
				/*
				 * The Use of RSVP with IETF Integrated Services (RFC 2210)
				 *
				 * 3.3.4. Controlled-Load Service ADSPEC data fragment
				 *
				 *      31            24 23           16 15            8 7             0
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 1   |     5 (a)     |x|  (b)        |            N-1 (c)            |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * 2   | Service-specific general parameter headers/values, if present |
				 *  .  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  .
				 * N   |                                                               |
				 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 */
adspec_controlled:		*checksum++ = ADSPEC_CONTROLLED_SERVICE;
				*checksum++ = FIELD_MUST_BE_ZERO;
				*((u_int16_t *)checksum) = htons(ADSPEC_CONTROLLED_LENGTH - \
				                           ADSPEC_MESSAGE_HEADER);
				checksum += sizeof(u_int16_t);
				/* Computing the Checksum offset. */
				offset += ADSPEC_CONTROLLED_LENGTH;
				break;
			default:
				break;
		}
	}

	/* 
	 * The RESV_CONFIRM Object Class is present for the following:
	 * 3.1.4 Resv Messages
	 * 3.1.9 Confirmation Messages
	 */
	if(o.rsvp.type == RSVP_MESSAGE_TYPE_RESV ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_RESVCONF){
		/*
		 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
		 *
		 * A.14 Resv_CONFIRM Class
		 *
		 * RESV_CONFIRM class = 15.
		 *
		 * o    IPv4 RESV_CONFIRM object: Class = 15, C-Type = 1
		 *
		 * +-------------+-------------+-------------+-------------+
		 * |            IPv4 Receiver Address (4 bytes)            |
		 * +-------------+-------------+-------------+-------------+
		 */
		*((u_int16_t *)checksum) = htons(RSVP_LENGTH_RESV_CONFIRM);
		checksum += sizeof(u_int16_t);
		*checksum++ = RSVP_OBJECT_RESV_CONFIRM;
		*checksum++ = 1;
		*((in_addr_t *)checksum) = INADDR_RND(o.rsvp.confirm_addr);
		checksum += sizeof(in_addr_t);
		/* Computing the Checksum offset. */
		offset += RSVP_LENGTH_RESV_CONFIRM;
	}

	/* 
	 * The STYLE Object Classes is present for the following:
	 * 3.1.4 Resv Messages
	 * 3.1.6 Resv Teardown Messages
	 * 3.1.8 Resv Error Messages
	 * 3.1.9 Confirmation Messages
	 */
	if(o.rsvp.type == RSVP_MESSAGE_TYPE_RESV     ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_RESVTEAR ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_RESVERR  ||
	   o.rsvp.type == RSVP_MESSAGE_TYPE_RESVCONF){
		/* 
		 * The SCOPE Object Classes is present for the following:
		 * 3.1.4 Resv Messages
		 * 3.1.6 Resv Teardown Messages
		 * 3.1.8 Resv Error Messages
		 */
		if(o.rsvp.type == RSVP_MESSAGE_TYPE_RESV     ||
		   o.rsvp.type == RSVP_MESSAGE_TYPE_RESVTEAR ||
		   o.rsvp.type == RSVP_MESSAGE_TYPE_RESVERR){
			/*
			 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
			 *
			 * A.6 SCOPE Class
			 *
			 * SCOPE class = 7.
			 *
			 * o    IPv4 SCOPE List object: Class = 7, C-Type = 1
			 *
			 * +-------------+-------------+-------------+-------------+
			 * |                IPv4 Src Address (4 bytes)             |
			 * +-------------+-------------+-------------+-------------+
			 * //                                                      //
			 * +-------------+-------------+-------------+-------------+
			 * |                IPv4 Src Address (4 bytes)             |
			 * +-------------+-------------+-------------+-------------+
			 */
			*((u_int16_t *)checksum) = htons(RSVP_LENGTH_SCOPE(o.rsvp.scope));
			checksum += sizeof(u_int16_t);
			*checksum++ = RSVP_OBJECT_SCOPE;
			*checksum++ = 1;
			/* Dealing with scope address(es). */
			for(counter = 0; counter < o.rsvp.scope ; counter ++){
				*((in_addr_t *)checksum) = INADDR_RND(o.rsvp.address[counter]);
				checksum += sizeof(in_addr_t);
			}
			/* Computing the Checksum offset. */
			offset += RSVP_LENGTH_SCOPE(o.rsvp.scope);
		}
		/*
		 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
		 *
		 * A.7 STYLE Class
		 *
		 * STYLE class = 8.
		 *
		 * o    STYLE object: Class = 8, C-Type = 1
		 *
		 * +-------------+-------------+-------------+-------------+
		 * |   Flags     |              Option Vector              |
		 * +-------------+-------------+-------------+-------------+
		 */
		*((u_int16_t *)checksum) = htons(RSVP_LENGTH_STYLE);
		checksum += sizeof(u_int16_t);
		*checksum++ = RSVP_OBJECT_STYLE;
		*checksum++ = 1;
		*checksum++ = FIELD_MUST_BE_ZERO;
		*((u_int32_t *)checksum) = htonl(__24BIT_RND(o.rsvp.style_opt) << 8);
		checksum += sizeof(in_addr_t) - 1;
		/* Computing the Checksum offset. */
		offset += RSVP_LENGTH_STYLE;
	}

	/* Computing the checksum. */
	rsvp->check   = o.bogus_csum ? \
		                __16BIT_RND(0) : \
	                cksum((u_int16_t *)rsvp, offset);

	/* GRE Encapsulation takes place. */
	if(o.encapsulated){
		/* Computing the checksum. */
		if((o.gre.options & GRE_OPTION_CHECKSUM) == GRE_OPTION_CHECKSUM)
			gre_sum->check  = o.bogus_csum ? \
					          __16BIT_RND(0) : \
				          cksum((u_int16_t *)gre, packet_size - sizeof(struct iphdr));
	}

	/* Sending packet. */
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
#endif  /* RSVP_C__ */
