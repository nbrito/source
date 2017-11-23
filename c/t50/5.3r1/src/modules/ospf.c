/* 
 * $Id: ospf.c,v 5.14 2011-04-17 11:38:39-03 nbrito Exp $
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
#ifndef OSPF_C__
#define OSPF_C__ 1

#include <common.h>


/*
 * External prototypes.
 */
extern inline size_t ospf_hdr_len(const u_int8_t, const u_int8_t, const u_int8_t, const u_int8_t);
extern inline size_t gre_opt_len(const u_int8_t, const u_int8_t);


/* 
 * Local Global Variables.
 */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 5.14 $";
#endif  /* __HAVE_DEBUG__ */


/* Function Name: OSPF packet header configuration.

   Description:   This function configures and sends the OSPF packet header.

   Targets:       N/A */
inline const void * ospf(const socket_t fd, const struct config_options o){
	/* GRE options size. */
	size_t greoptlen = gre_opt_len(o.gre.options, o.encapsulated);
	/* OSPF options? */
	const u_int8_t ospf_options = __8BIT_RND(o.ospf.options);
	/* OSPF LLS Header? */
	u_int8_t lls = ((ospf_options & OSPF_OPTION_LLS) == OSPF_OPTION_LLS ? 1 : 0);
	/* OSPF Header length. */
	size_t ospf_length = ospf_hdr_len(o.ospf.type, o.ospf.neighbor, o.ospf.lsa_type, o.ospf.dd_include_lsa);
	/* Packet size. */
	const u_int32_t packet_size = sizeof(struct iphdr)           + \
	                              greoptlen                      + \
	                              sizeof(struct ospf_hdr)        + \
	                              sizeof(struct ospf_auth_hdr)   + \
	                              ospf_length                    + \
	                              auth_hmac_md5_len(o.ospf.auth) + \
	                              ospf_tlv_len(o.ospf.type, lls, o.ospf.auth);
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
	/* OSPF header. */
	static struct ospf_hdr * ospf;
	/*  OSPF Auth header, LSA header and LLS TLVs. */
	static struct ospf_auth_hdr * ospf_auth;
	static struct ospf_lsa_hdr * ospf_lsa;
	static struct ospf_lls_hdr * ospf_lls;

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
		                   sizeof(struct ospf_hdr)        + \
		                   sizeof(struct ospf_auth_hdr)   + \
		                   ospf_length                    + \
		                   auth_hmac_md5_len(o.ospf.auth) + \
		                   ospf_tlv_len(o.ospf.type, lls, o.ospf.auth));
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

	/* OSPF Header structure making a pointer to  IP Header structure. */
	ospf          = (struct ospf_hdr *)((u_int8_t *)ip + sizeof(struct iphdr) + greoptlen);
	ospf->version = OSPFVERSION;
	ospf->type    = o.ospf.type;
	/*
	 * OSPF Version 2 (RFC 2328)
	 *
	 * D.3 Cryptographic authentication
	 *
	 * The message digest appended to  the OSPF packet is not actually
	 * considered part of the OSPF protocol packet: the message digest
	 * is not included in the OSPF header's packet length, although it
	 * is included in the packet's IP header length field.
	 */
	ospf->length  = htons(o.ospf.length ? \
		                o.ospf.length : \
	                sizeof(struct ospf_hdr) + \
	                sizeof(struct ospf_auth_hdr)  + \
	                ospf_length);
	ospf->rid     = INADDR_RND(o.ospf.rid);
	ospf->aid     = o.ospf.AID ? INADDR_RND(o.ospf.aid) : o.ospf.aid;
	ospf->check   = 0;

	/* OSPF Authentication Header structure making a pointer to OSPF Header structure. */
	ospf_auth       = (struct ospf_auth_hdr *)((u_int8_t *)ospf + sizeof(struct ospf_hdr));
	/* Identifiyingt whether to use Authentication or not. */
	if(o.ospf.auth){
		/*
		 * OSPF Version 2 (RFC 2328)
		 *
		 * D.3 Cryptographic authentication
		 *
		 *   0                   1                   2                   3
		 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |              0                |    Key ID     | Auth Data Len |
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |                 Cryptographic sequence number                 |
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		ospf->autype        = htons(AUTH_TYPE_HMACMD5);
		ospf_auth->reserved = FIELD_MUST_BE_ZERO;
		ospf_auth->key_id   = __8BIT_RND(o.ospf.key_id);
		ospf_auth->length   = auth_hmac_md5_len(o.ospf.auth);
		ospf_auth->sequence = htonl(__32BIT_RND(o.ospf.sequence));
	}else{
		/*
		 * OSPF Version 2 (RFC 2328)
		 *
		 * A.3.1 The OSPF packet header
		 *
		 *   0                   1                   2                   3
		 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |                       Authentication                          |
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |                       Authentication                          |
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		ospf->autype        = AUTH_TYPE_HMACNUL;
		ospf_auth->reserved = FIELD_MUST_BE_ZERO;
		ospf_auth->key_id   = FIELD_MUST_BE_ZERO;
		ospf_auth->length   = FIELD_MUST_BE_ZERO;
		ospf_auth->sequence = FIELD_MUST_BE_ZERO;
	}
	/* Computing the Checksum offset. */
	offset = sizeof(struct ospf_auth_hdr);

	/* Storing both Checksum and Packet. */
	checksum = (u_int8_t *)ospf_auth + offset;

	/* Identifying the OSPF Type and building it. */
	switch(o.ospf.type){
		case OSPF_TYPE_HELLO:
			/*
			 * OSPF Version 2 (RFC 2328)
			 *
			 * A.3.2 The Hello packet
			 *
			 *   0                   1                   2                   3
			 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                        Network Mask                           |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |         HelloInterval         |    Options    |    Rtr Pri    |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                     RouterDeadInterval                        |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                      Designated Router                        |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                   Backup Designated Router                    |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                          Neighbor                             |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                              ...                              |
			 */
			*((in_addr_t *)checksum) = NETMASK_RND(o.ospf.netmask);
			checksum += sizeof(in_addr_t);
			*((u_int16_t *)checksum) = htons(__16BIT_RND(o.ospf.hello_interval));
			checksum += sizeof(u_int16_t);
			*checksum++ = ospf_options;
			*checksum++ = __8BIT_RND(o.ospf.hello_priority);
			*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.ospf.hello_dead));
			checksum += sizeof(u_int32_t);
			*((in_addr_t *)checksum) = INADDR_RND(o.ospf.hello_design);
			checksum += sizeof(in_addr_t);
			*((in_addr_t *)checksum) = INADDR_RND(o.ospf.hello_backup);
			checksum += sizeof(in_addr_t);
			/* Computing the Checksum offset. */
			offset += OSPF_TLEN_HELLO;
			/* Dealing with neighbor address(es). */
			for(counter = 0 ; counter < o.ospf.neighbor ; counter++){
				*((in_addr_t *)checksum) = INADDR_RND(o.ospf.address[counter]);
				checksum += sizeof(in_addr_t);
			}
			/* Computing the Checksum offset. */
			offset += OSPF_TLEN_NEIGHBOR(o.ospf.neighbor);
			break;
		case OSPF_TYPE_DD:
			/*
			 * OSPF Version 2 (RFC 2328)
			 *
			 * A.3.3 The Database Description packet
			 *
			 *   0                   1                   2                   3
			 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |         Interface MTU         |    Options    |0|0|0|0|0|I|M|MS
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                     DD sequence number                        |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                                                               |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-                      An LSA Header                          -+
			 *  |                                                               |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */
			*((u_int16_t *)checksum) = htons(__16BIT_RND(o.ospf.dd_mtu));
			checksum += sizeof(u_int16_t);
			*checksum++ = ospf_options;
			*checksum++ = __3BIT_RND(o.ospf.dd_dbdesc);
			*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.ospf.dd_sequence));
			checksum += sizeof(u_int32_t);
			/* Computing the Checksum offset. */
			offset += OSPF_TLEN_DD;
			break;
		case OSPF_TYPE_LSREQUEST:
			/*
			 * OSPF Version 2 (RFC 2328)
			 *
			 * A.3.4 The Link State Request packet
			 *
			 *   0                   1                   2                   3
			 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                          LS type                              |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                       Link State ID                           |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                     Advertising Router                        |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */
			*((u_int32_t *)checksum) = htonl(o.ospf.lsa_type);
			checksum += sizeof(u_int32_t);
			*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.ospf.lsa_lsid));
			checksum += sizeof(u_int32_t);
			*((in_addr_t *)checksum) = INADDR_RND(o.ospf.lsa_router);
			checksum += sizeof(in_addr_t);
			/* Computing the Checksum offset. */
			offset += OSPF_TLEN_LSREQUEST;
			break;
		case OSPF_TYPE_LSUPDATE:
			/*
			 * OSPF Version 2 (RFC 2328)
			 *
			 * A.3.5 The Link State Update packet
			 *
			 *   0                   1                   2                   3
			 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                            # LSAs                             |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                                                               |
			 *  +-                                                            +-+
			 *  |                             LSAs                              |
			 *  +-                                                            +-+
			 *  |                              ...                              |
			 */
			*((in_addr_t *)checksum) = htonl(1);
			checksum += sizeof(u_int32_t);
			/* Going to the OSPF LSA Header and building it. */
			goto build_ospf_lsa;
			/* Identifying the LSA Type and building it. */
build_ospf_lsupdate:	if(o.ospf.lsa_type == LSA_TYPE_ROUTER){
				/* Setting the correct OSPF LSA Header length. */
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_ROUTER);
				/*
				 * The OSPF Not-So-Stubby Area (NSSA) Option (RFC 3101)
				 *
				 * Appendix B: Router-LSAs
				 *
				 *   0                   1                   2                   3
				 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |  0  Nt|W|V|E|B|        0      |            # links            |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                          Link ID                              |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                         Link Data                             |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |     Type      |     # TOS     |            metric             |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 */
				*checksum++ = __5BIT_RND(o.ospf.lsa_flags);
				*checksum++ = FIELD_MUST_BE_ZERO; 
				*((u_int16_t *)checksum) = htons(1);
				checksum += sizeof(u_int16_t);
				*((in_addr_t *)checksum) = INADDR_RND(o.ospf.lsa_link_id);
				checksum += sizeof(in_addr_t);
				*((in_addr_t *)checksum) = NETMASK_RND(o.ospf.lsa_link_data);
				checksum += sizeof(in_addr_t);
				*checksum++ = __8BIT_RND(o.ospf.lsa_link_type);
				*checksum++ = FIELD_MUST_BE_ZERO;
				*((u_int16_t *)checksum) = htons(__16BIT_RND(o.ospf.lsa_metric));
				checksum += sizeof(u_int16_t);
				/* Computing the Checksum offset. */
				offset += OSPF_TLEN_LSUPDATE;
				offset += LSA_TLEN_ROUTER;
				/* Computing the checksum. */
				ospf_lsa->check      =  o.bogus_csum ? \
				                                __16BIT_RND(0) : \
				                        cksum((u_int16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_ROUTER);
			}else if(o.ospf.lsa_type == LSA_TYPE_NETWORK){
				/* Setting the correct OSPF LSA Header length. */
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_NETWORK);
				/*
				 * OSPF Version 2 (RFC 2328)
				 *
				 * A.4.3 Network-LSAs
				 *
				 *   0                   1                   2                   3
				 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                         Network Mask                          |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                        Attached Router                        |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 */
				*((in_addr_t *)checksum) = NETMASK_RND(o.ospf.netmask);
				checksum += sizeof(in_addr_t);
				*((in_addr_t *)checksum) = INADDR_RND(o.ospf.lsa_attached);
				checksum += sizeof(in_addr_t);
				/* Computing the Checksum offset. */
				offset += OSPF_TLEN_LSUPDATE;
				offset += LSA_TLEN_NETWORK;
				/* Computing the checksum. */
				ospf_lsa->check      =  o.bogus_csum  ? \
				                                __16BIT_RND(0) : \
				                        cksum((u_int16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_NETWORK);
			}else if(o.ospf.lsa_type == LSA_TYPE_SUMMARY_IP ||
			         o.ospf.lsa_type == LSA_TYPE_SUMMARY_AS){
				/* Setting the correct OSPF LSA Header length. */
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_SUMMARY);
				/*
				 * OSPF Version 2 (RFC 2328)
				 *
				 * A.4.4 Summary-LSAs
				 *
				 *   0                   1                   2                   3
				 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                         Network Mask                          |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |      0        |                  metric                       |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 */
				*((in_addr_t *)checksum) = NETMASK_RND(o.ospf.netmask);
				checksum += sizeof(in_addr_t);
				*checksum++ = FIELD_MUST_BE_ZERO;
				*((u_int32_t *)checksum) = htonl(__24BIT_RND(o.ospf.lsa_metric) << 8);
				checksum += sizeof(u_int32_t) - 1;
				/* Computing the Checksum offset. */
				offset += OSPF_TLEN_LSUPDATE;
				offset += LSA_TLEN_SUMMARY;
				/* Computing the checksum. */
				ospf_lsa->check      =  o.bogus_csum ? \
				                                __16BIT_RND(0) : \
				                        cksum((u_int16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_SUMMARY);
			}else if(o.ospf.lsa_type == LSA_TYPE_ASBR ||
			         o.ospf.lsa_type == LSA_TYPE_NSSA){
				/* Setting the correct OSPF LSA Header length. */
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_ASBR);
				/*
				 * OSPF Version 2 (RFC 2328)
				 *
				 * A.4.5 AS-external-LSAs
				 *
				 * The OSPF NSSA Option (RFC 1587)
				 *
				 * Appendix A: Type-7 Packet Format
				 *
				 *   0                   1                   2                   3
				 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                         Network Mask                          |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |E|     0       |                  metric                       |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                      Forwarding address                       |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                      External Route Tag                       |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 */
				*((in_addr_t *)checksum) = NETMASK_RND(o.ospf.netmask);
				checksum += sizeof(in_addr_t);
				*checksum++ = (o.ospf.lsa_larger ? \
					              0x80 : \
				              0x00);
				*((u_int32_t *)checksum) = htonl(__24BIT_RND(o.ospf.lsa_metric) << 8);
				checksum += sizeof(u_int32_t) - 1;
				*((in_addr_t *)checksum) = INADDR_RND(o.ospf.lsa_forward);
				checksum += sizeof(in_addr_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.ospf.lsa_external));
				checksum += sizeof(u_int32_t);
				/* Computing the Checksum offset. */
				offset += OSPF_TLEN_LSUPDATE;
				offset += LSA_TLEN_ASBR;
				/* Computing the checksum. */
				ospf_lsa->check      =  o.bogus_csum ? \
				                                __16BIT_RND(0) : \
				                        cksum((u_int16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_ASBR);
			}else if(o.ospf.lsa_type == LSA_TYPE_MULTICAST){
				/* Setting the correct OSPF LSA Header length. */
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_MULTICAST);
				/*
				 * Multicast Extensions to OSPF (RFC 1584)
				 *
				 * A.3 Group-membership-LSA
				 *
				 *   0                   1                   2                   3
				 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                        Vertex type                            |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                         Vertex ID                             |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 */
				*((u_int32_t *)checksum) = htonl(__2BIT_RND(o.ospf.vertex_type));
				checksum += sizeof(u_int32_t);
				*((in_addr_t *)checksum) = INADDR_RND(o.ospf.vertex_id);
				checksum += sizeof(in_addr_t);
				/* Computing the Checksum offset. */
				offset += OSPF_TLEN_LSUPDATE;
				offset += LSA_TLEN_MULTICAST;
				/* Computing the checksum. */
				ospf_lsa->check      =  o.bogus_csum ? \
				                                __16BIT_RND(0) : \
				                        cksum((u_int16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_MULTICAST);
			/* Building a generic OSPF LSA Header. */
			}else{
				/* Setting the correct OSPF LSA Header length. */
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_GENERIC(0));
				/* Computing the Checksum offset. */
				offset += OSPF_TLEN_LSUPDATE;
				offset += LSA_TLEN_GENERIC(0);
				/* Computing the checksum. */
				ospf_lsa->check      =  o.bogus_csum ? \
				                                __16BIT_RND(0) : \
				                        cksum((u_int16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_GENERIC(0));
			}
			break;
		case OSPF_TYPE_LSACK:
			/*
			 * OSPF Version 2 (RFC 2328)
			 *
			 * A.3.6 The Link State Acknowledgment packet
			 *
			 *   0                   1                   2                   3
			 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                                                               |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-                         An LSA Header                       -+
			 *  |                                                               |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */
			/* Going to the OSPF LSA Header and building it. */
			goto build_ospf_lsa;
			break;
		default:
			break;
	}

	/*
	 * OSPF Version 2 (RFC 2328)
	 *
	 * A.3.3 The Database Description packet
	 *
	 * The rest of the packet consists of a (possibly partial) list of the
	 * link-state database's pieces. Each LSA in the database is described
	 * by its LSA header.   The LSA header is documented in Section A.4.1.
	 * It contains all  the information required to uniquely identify both
	 * the LSA and the LSA's current instance.
	 */
	if(o.ospf.type == OSPF_TYPE_DD){
		if(o.ospf.dd_include_lsa){
			/* OSPF LSA Header structure making a pointer to Checksum. */
build_ospf_lsa:		ospf_lsa             = (struct ospf_lsa_hdr *)((u_int8_t *)checksum);
			ospf_lsa->age        = htons(__16BIT_RND(o.ospf.lsa_age));
			/* Deciding whether age or not. */
			if(o.ospf.lsa_dage)
				ospf_lsa->age        |= 0x80;
			ospf_lsa->type       = o.ospf.lsa_type;
			ospf_lsa->options    = ospf_options;
			ospf_lsa->lsid       = INADDR_RND(o.ospf.lsa_lsid);
			ospf_lsa->router     = INADDR_RND(o.ospf.lsa_router);
			ospf_lsa->sequence   = htonl(__32BIT_RND(o.ospf.lsa_sequence));
			ospf_lsa->check      = 0;
			checksum += sizeof(struct ospf_lsa_hdr);
			/* Returning to the OSPF type LSUpdate and continue builing it. */
			if(o.ospf.type == OSPF_TYPE_LSUPDATE)
				goto build_ospf_lsupdate;
			/*
			 * At this point, the code does not need to build the entiry LSA Type
			 * Header. It just needs to set the correct OSPF LSA Header length.
			 */
			if(o.ospf.lsa_type == LSA_TYPE_ROUTER)
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_ROUTER);
			else if(o.ospf.lsa_type == LSA_TYPE_NETWORK)
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_NETWORK);
			else if(o.ospf.lsa_type == LSA_TYPE_SUMMARY_IP ||
			        o.ospf.lsa_type == LSA_TYPE_SUMMARY_AS)
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_SUMMARY);
			else if(o.ospf.lsa_type == LSA_TYPE_ASBR ||
			        o.ospf.lsa_type == LSA_TYPE_NSSA)
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_ASBR);
			else if(o.ospf.lsa_type == LSA_TYPE_MULTICAST)
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_MULTICAST);
			else
				ospf_lsa->length     = htons(o.ospf.length ? \
					                       o.ospf.length : \
				                       LSA_TLEN_GENERIC(0));
			/* Computing the Checksum offset. */
			offset += LSA_TLEN_GENERIC(0);
			/* Computing the checksum. */
			ospf_lsa->check      =  o.bogus_csum ? \
		                                __16BIT_RND(0) : \
			                        cksum((u_int16_t *)ospf_lsa, LSA_TLEN_GENERIC(0));
		}
	}

	/*
	 * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
	 */
	for(counter = 0 ; counter < auth_hmac_md5_len(o.ospf.auth) ; counter++)
		*checksum++ = __8BIT_RND(0);
	/* Computing the Checksum offset. */
	offset += auth_hmac_md5_len(o.ospf.auth);
	
	/*
	 * OSPF Link-Local Signaling (RFC 5613)
	 *
	 * 2.1.  L-Bit in Options Field
	 *
	 * The L-bit MUST NOT be set except in Hello and DD packets that contain
	 * an LLS block.
	 */
	if(o.ospf.type == OSPF_TYPE_HELLO ||
	   o.ospf.type == OSPF_TYPE_DD){
		if(lls){
			/* OSPF LLS TLVs structure making a pointer to Checksum. */
			ospf_lls         = (struct ospf_lls_hdr *)((u_int8_t *)checksum);
			ospf_lls->length = htons(o.ospf.length ? \
	                                           o.ospf.length : \
			                   ospf_tlv_len(o.ospf.type, lls, o.ospf.auth)/4);
			ospf_lls->check  = 0;
			checksum += sizeof(struct ospf_lls_hdr);
			/*
			 * OSPF Link-Local Signaling (RFC 5613)
			 *
			 * 2.4.  Extended Options and Flags TLV
			 *
			 *   0                   1                   2                   3
			 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |             1                 |            4                  |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 *  |                  Extended Options and Flags                   |
			 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */
			*((u_int16_t *)checksum) = htons(OSPF_TLV_EXTENDED);
			checksum += sizeof(u_int16_t);
			*((u_int16_t *)checksum) = htons(OSPF_LEN_EXTENDED);
			checksum += sizeof(u_int16_t);
			*((u_int32_t *)checksum) = htonl(o.ospf.lls_options);
			checksum += sizeof(u_int32_t);
			/*
			 * OSPF Link-Local Signaling (RFC 5613)
			 *
			 * 2.2.  LLS Data Block
			 *
			 * Note that if the OSPF packet is cryptographically authenticated, the
			 * LLS data block MUST also be cryptographically authenticated.
			 */
			if(o.ospf.auth){
				/*
				 * OSPF Link-Local Signaling (RFC 5613)
				 *
				 * 2.5.  Cryptographic Authentication TLV (OSPFv2 ONLY)
				 *
				 *   0                   1                   2                   3
				 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |              2                |         AuthLen               |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                         Sequence Number                       |
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *  |                                                               |
				 *  .                                                               .
				 *  .                           AuthData                            .
				 *  .                                                               .
				 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *
				 * This document defines a special TLV that is used for cryptographic
				 * authentication (CA-TLV) of the LLS data block.  This TLV MUST only
				 * be included in the LLS block  when cryptographic authentication is
				 * enabled on the corresponding interface.
				 *
				 * The CA-TLV MUST NOT appear more than once in the LLS block.  Also,
				 * when present,  this TLV MUST be the last TLV in the LLS block.  If 
				 * it appears more than once,  only the first occurrence is processed 
				 * and any others MUST be ignored.
				 */
				*((u_int16_t *)checksum) = htons(OSPF_TLV_CRYPTO);
				checksum += sizeof(u_int16_t);
				*((u_int16_t *)checksum) = htons(OSPF_LEN_CRYPTO);
				checksum += sizeof(u_int16_t);
				*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.ospf.sequence));
				checksum += sizeof(u_int32_t);
				/*
				 * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
				 */
				for(counter = 0 ; counter < auth_hmac_md5_len(o.ospf.auth) ; counter++)
					*checksum++ = __8BIT_RND(0);
			/*
			 * OSPF Link-Local Signaling (RFC 5613)
			 *
			 * 2.2.  LLS Data Block
			 *
			 * Note that if the OSPF packet is cryptographically authenticated, the
			 * LLS data block MUST also be cryptographically authenticated. In this
			 * case, the regular LLS checksum is not calculated, but is instead set
			 * to 0.
			 */
			}else{
				/* Computing the checksum. */
				ospf_lls->check  =  o.bogus_csum ? \
			                            __16BIT_RND(0) : \
				                    cksum((u_int16_t *)ospf_lls, ospf_tlv_len(o.ospf.type, lls, o.ospf.auth));
			}
			/* Computing the Checksum offset. */
			offset += ospf_tlv_len(o.ospf.type, lls, o.ospf.auth);
		}

	}

	/*
	 * OSPF Version 2 (RFC 2328)
	 *
	 * D.4.3 Generating Cryptographic authentication
	 *
	 * (2) The checksum field in the standard OSPF header is not
         *     calculated, but is instead set to 0.
	 */
	if(!o.ospf.auth)
		/* Computing the checksum. */
		ospf->check   = o.bogus_csum ? \
			        __16BIT_RND(0) : \
			        cksum((u_int16_t *)ospf, sizeof(struct ospf_hdr) + offset);

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
#endif  /* OSPF_C__ */
