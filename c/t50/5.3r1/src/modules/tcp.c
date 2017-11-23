/* 
 * $Id: tcp.c,v 5.26 2011-04-17 11:38:39-03 nbrito Exp $
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
#ifndef TCP_C__
#define TCP_C__ 1

#include <common.h>


/*
 * External prototypes.
 */
extern inline size_t tcp_options_len(const u_int8_t, const u_int8_t, const u_int8_t);
extern inline size_t gre_opt_len(const u_int8_t, const u_int8_t);


/* 
 * Local Global Variables.
 */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 5.26 $";
#endif  /* __HAVE_DEBUG__ */


/* Function Name: TCP packet header configuration.

   Description:   This function configures and sends the TCP packet header.

   Targets:       N/A */
inline const void * tcp(const socket_t fd, const struct config_options o){
	/* GRE options size. */
	size_t greoptlen = gre_opt_len(o.gre.options, o.encapsulated);
	/* TCP options size. */
	size_t tcpolen = tcp_options_len(o.tcp.options, o.tcp.md5, o.tcp.auth);
	/* TCP options padding and TCP options total size. */
	const u_int32_t tcpopad = TCPOLEN_PADDING(tcpolen), tcpopt = tcpolen + tcpopad;
	/* Packet size. */
	const u_int32_t packet_size = sizeof(struct iphdr)  + \
	                              greoptlen             + \
	                              sizeof(struct tcphdr) + \
	                              tcpopt;
	/* Checksum offset, GRE offset and Counter. */
	static u_int32_t offset = 0, greoffset = 0, counter = 0;
	/* Packet and Checksum. */
	u_int8_t packet[packet_size], * checksum = NULL;
	/* Socket address, IP header. */
	static struct sockaddr_in sin;
	static struct iphdr * ip;
	/* GRE header, GRE Checksum header and GRE Encapsulated IP Header. */
	static struct gre_hdr * gre;
	static struct gre_sum_hdr * gre_sum;
	static struct gre_key_hdr * gre_key;
	static struct gre_seq_hdr * gre_seq;
	static struct iphdr * gre_ip;
	/* TCP header and PSEUDO header. */
	static struct tcphdr * tcp;
	static struct psdhdr * pseudo;

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
		                   sizeof(struct tcphdr)      + \
		                   tcpopt);
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
	 * The RFC 793 has defined a 4-bit field in the TCP header which encodes the size
	 * of the header in 4-byte words.  Thus the maximum header size is 15*4=60 bytes. 
	 * Of this, 20 bytes are taken up by non-options fields of the TCP header,  which
	 * leaves 40 bytes (TCP header * 2) for options.
	 */
	if(tcpopt > (sizeof(struct tcphdr)*2)){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr,
			"%s(): TCP Options size (%d bytes) is bigger than two times TCP Header size\n",
			__FUNCTION__,
			tcpopt);
		fflush(stderr);
		exit(EXIT_FAILURE);
	}

	/* TCP Header structure making a pointer to IP Header structure. */
	tcp          = (struct tcphdr *)((u_int8_t *)ip + sizeof(struct iphdr) + greoptlen);
	tcp->source  = htons(IPPORT_RND(o.source));
	tcp->dest    = htons(IPPORT_RND(o.dest));
	tcp->res1    = TCP_RESERVED_BITS;
	tcp->doff    = o.tcp.doff ? \
		               o.tcp.doff : \
	               ((sizeof(struct tcphdr) + \
	               tcpopt)/4);
	tcp->fin     = o.tcp.fin;
	tcp->syn     = o.tcp.syn;
	tcp->syn     = o.tcp.syn;
	tcp->seq     = o.tcp.syn ? \
		               htonl(__32BIT_RND(o.tcp.sequence)) : \
	               0;
	tcp->rst     = o.tcp.rst;
	tcp->psh     = o.tcp.psh;
	tcp->ack     = o.tcp.ack;
	tcp->ack_seq = o.tcp.ack ? \
		               htonl(__32BIT_RND(o.tcp.acknowledge)) : \
	               0;
	tcp->urg     = o.tcp.urg;
	tcp->urg_ptr = o.tcp.urg ? \
		               htons(__16BIT_RND(o.tcp.urg_ptr)) : \
	               0;
	tcp->ece     = o.tcp.ece;
	tcp->cwr     = o.tcp.cwr;
	tcp->window  = htons(__16BIT_RND(o.tcp.window));
	tcp->check   = 0;
	/* Computing the Checksum offset. */
	offset = sizeof(struct tcphdr);

	/* Building TCP Options and storing both Checksum and Packet. */
	checksum = (u_int8_t *)tcp + offset;
	/*
	 * Transmission Control Protocol (TCP) (RFC 793)
	 *
	 *    TCP Maximum Segment Size
	 *
	 *    Kind: 2
	 *
	 *    Length: 4 bytes
	 *
	 *    +--------+--------+---------+--------+
	 *    |00000010|00000100|   max seg size   |
	 *    +--------+--------+---------+--------+
	*/
	if((o.tcp.options & TCP_OPTION_MSS) == TCP_OPTION_MSS){
		*checksum++ = TCPOPT_MSS;
		*checksum++ = TCPOLEN_MSS;
		*((u_int16_t *)checksum) = htons(__16BIT_RND(o.tcp.mss));
		checksum   += sizeof(u_int16_t);
	}
	/*
	 * TCP Extensions for High Performance (RFC 1323)
	 *
	 *    TCP Window Scale Option (WSopt):
	 *
	 *    Kind: 3
	 *
	 *    Length: 3 bytes
	 *
	 *    +--------+--------+--------+
	 *    |00000011|00000011| shift  |
	 *    +--------+--------+--------+
	 */
	if((o.tcp.options & TCP_OPTION_WSOPT) == TCP_OPTION_WSOPT){
		*checksum++ = TCPOPT_WSOPT;
		*checksum++ = TCPOLEN_WSOPT;
		*checksum++ = __8BIT_RND(o.tcp.wsopt);
	}
	/*
	 * TCP Extensions for High Performance (RFC 1323)
	 *
	 *    TCP Timestamps Option (TSopt):
	 *
	 *    Kind: 8
	 *
	 *    Length: 10 bytes
	 *
	 *                      +--------+--------+
	 *                      |00001000|00001010|
	 *    +--------+--------+--------+--------+
	 *    |         TS Value (TSval)          |
	 *    +--------+--------+--------+--------+
	 *    |       TS Echo Reply (TSecr)       |
	 *    +--------+--------+--------+--------+
	 */
	if((o.tcp.options & TCP_OPTION_TSOPT) == TCP_OPTION_TSOPT){
		/*
		 * TCP Extensions for High Performance (RFC 1323)
		 *
		 * APPENDIX A:  IMPLEMENTATION SUGGESTIONS
		 *
		 *   The following layouts are recommended for sending options on non-SYN
		 *   segments, to achieve maximum feasible alignment of 32-bit and 64-bit
		 *   machines.
		 *
		 *
		 *       +--------+--------+--------+--------+
		 *       |   NOP  |  NOP   |  TSopt |   10   |
		 *       +--------+--------+--------+--------+
		 *       |          TSval   timestamp        |
		 *       +--------+--------+--------+--------+
		 *       |          TSecr   timestamp        |
		 *       +--------+--------+--------+--------+
		 */
		if(!o.tcp.syn)
			for( ; tcpolen & 3 ; tcpolen++)
				*checksum++ = TCPOPT_NOP;
		*checksum++ = TCPOPT_TSOPT;
		*checksum++ = TCPOLEN_TSOPT;
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.tcp.tsval));
		checksum   += sizeof(u_int32_t);
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.tcp.tsecr));
		checksum   += sizeof(u_int32_t);
	}
	/*
	 * TCP Extensions for Transactions Functional Specification (RFC 1644)
	 *
	 *    CC Option:
	 *
	 *    Kind: 11
	 *
	 *    Length: 6 bytes
	 *
	 *                      +--------+--------+
	 *                      |00001011|00000110|
	 *    +--------+--------+--------+--------+
	 *    |     Connection Count:  SEG.CC     |
	 *    +--------+--------+--------+--------+
	 */
	if((o.tcp.options & TCP_OPTION_CC) == TCP_OPTION_CC){
		*checksum++ = TCPOPT_CC;
		*checksum++ = TCPOLEN_CC;
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.tcp.cc));
		checksum   += sizeof(u_int32_t);


		/*
		 * TCP Extensions for Transactions Functional Specification (RFC 1644)
		 *
		 * 3.1  Data Structures
		 *
		 * This option may be sent in an initial SYN segment,  and it may be sent
		 * in other segments if a  CC or CC.NEW option has been received for this
		 * incarnation of the connection.  Its  SEG.CC  value  is  the TCB.CCsend
		 *  value from the sender's TCB.
		 */
		tcp->syn     = 1;
		tcp->seq     = htonl(__32BIT_RND(o.tcp.sequence));
	}
	/*
	 * TCP Extensions for Transactions Functional Specification (RFC 1644)
	 *
	 *    CC.NEW Option:
	 *
	 *    Kind: 12
	 *
	 *    Length: 6 bytes
	 *
	 *                      +--------+--------+
	 *                      |00001100|00000110|
	 *    +--------+--------+--------+--------+
	 *    |     Connection Count:  SEG.CC     |
	 *    +--------+--------+--------+--------+
	 *
	 *    CC.ECHO Option:
	 *
	 *    Kind: 13
	 *
	 *    Length: 6 bytes
	 *
	 *                      +--------+--------+
	 *                      |00001101|00000110|
	 *    +--------+--------+--------+--------+
	 *    |     Connection Count:  SEG.CC     |
	 *    +--------+--------+--------+--------+
	 */
	if((o.tcp.options & TCP_OPTION_CC_NEXT) == TCP_OPTION_CC_NEXT){
		*checksum++ = o.tcp.cc_new ? \
			              TCPOPT_CC_NEW : \
		              TCPOPT_CC_ECHO;
		*checksum++ = TCPOLEN_CC;
		*((u_int32_t *)checksum) = htonl(o.tcp.cc_new ? \
			                           __32BIT_RND(o.tcp.cc_new) : \
		                           __32BIT_RND(o.tcp.cc_echo));
		checksum   += sizeof(u_int32_t);
		/*
		 * TCP Extensions for Transactions Functional Specification (RFC 1644)
		 *
		 * 3.1  Data Structures
		 *
		 * This  option  may be sent instead of a CC option in an  initial  <SYN> 
		 * segment (i.e., SYN but not ACK bit), to indicate that the SEG.CC value
		 * may not be larger than the previous value.   Its  SEG.CC  value is the
		 * TCB.CCsend value from the sender's TCB.
		 */
		if(o.tcp.cc_new){
			tcp->syn     = 1;
			tcp->seq     = htonl(__32BIT_RND(o.tcp.sequence));
		/*
		 * TCP Extensions for Transactions Functional Specification (RFC 1644)
		 *
		 * 3.1  Data Structures
		 *
		 * This  option  may be sent instead of a CC option in an  initial  <SYN> 
		 * This  option must be sent  (in addition to a CC option)  in a  segment 
		 * containing both a  SYN and an  ACK bit,  if  the initial  SYN  segment
		 * contained a CC or CC.NEW option.  Its SEG.CC value is the SEG.CC value
		 * from the initial SYN.
		 */
		}else{
			tcp->syn     = 1;
			tcp->seq     = htonl(__32BIT_RND(o.tcp.sequence));
			tcp->ack     = 1;
			tcp->ack_seq = htonl(__32BIT_RND(o.tcp.acknowledge));
		}

	}
	/*
	 * TCP Selective Acknowledgement Options (SACK) (RFC 2018)
	 *
	 *    TCP Sack-Permitted Option:
	 *
	 *    Kind: 4
	 *
	 *    Length: 2 bytes
	 *
	 *    +--------+--------+
	 *    |00000100|00000010|
	 *    +--------+--------+
	 */
	if((o.tcp.options & TCP_OPTION_SACK_OK) == TCP_OPTION_SACK_OK){
		*checksum++ = TCPOPT_SACK_OK;
		*checksum++ = TCPOLEN_SACK_OK;
	}
	/*
	 * TCP Selective Acknowledgement Options (SACK) (RFC 2018)
	 *
	 *    TCP SACK Option:
	 *
	 *    Kind: 5
	 *
	 *    Length: Variable
	 *
	 *                      +--------+--------+
	 *                      |00000101| Length |
	 *    +--------+--------+--------+--------+
	 *    |      Left Edge of 1st Block       |
	 *    +--------+--------+--------+--------+
	 *    |      Right Edge of 1st Block      |
	 *    +--------+--------+--------+--------+
	 *    |                                   |
	 *    /            . . .                  /
	 *    |                                   |
	 *    +--------+--------+--------+--------+
	 *    |      Left Edge of nth Block       |
	 *    +--------+--------+--------+--------+
	 *    |      Right Edge of nth Block      |
	 *    +--------+--------+--------+--------+
	 */
	if((o.tcp.options & TCP_OPTION_SACK_EDGE) == TCP_OPTION_SACK_EDGE){
		*checksum++ = TCPOPT_SACK_EDGE;
		/* (((sizeof(u_int32_t ) * 2) * 1) + TCPOLEN_SACK_OK = (8 * 1) + 2 = 10 */
		*checksum++ = TCPOLEN_SACK_EDGE(1);
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.tcp.sack_left));
		checksum   += sizeof(u_int32_t);
		*((u_int32_t *)checksum) = htonl(__32BIT_RND(o.tcp.sack_right));
		checksum   += sizeof(u_int32_t);
	}
	/*
	 *  Protection of BGP Sessions via the TCP MD5 Signature Option (RFC 2385)
	 *
	 *    TCP MD5 Option:
	 *
	 *    Kind: 19
	 *
	 *    Length: 18 bytes
	 *
	 *    +--------+--------+--------+--------+
	 *    |00010011|00010010|   MD5 digest... |
	 *    +--------+--------+--------+--------+
	 *    |        ...digest (con't)...       |
	 *    +-----------------------------------+
	 *    |                ...                |
	 *    +-----------------------------------+
	 *    |                ...                |
	 *    +-----------------+-----------------+
	 *    |...digest (con't)|
	 *    +-----------------+
	 */
	if(o.tcp.md5){
		*checksum++ = TCPOPT_MD5;
		*checksum++ = TCPOLEN_MD5;
		/*
		 * The Authentication key uses HMAC-MD5 digest.
		 */
		for(counter = 0 ; counter < auth_hmac_md5_len(o.tcp.md5) ; counter++)
			*checksum++ = __8BIT_RND(0);
	}
	/*
	 *  The TCP Authentication Option (RFC 5925)
	 *
	 *    TCP-AO Option:
	 *
	 *    Kind: 29
	 *
	 *    Length: 20 bytes
	 *
	 *    +--------+--------+--------+--------+
	 *    |00011101|00010100| Key ID |Next Key|
	 *    +--------+--------+--------+--------+
	 *    |              MAC ...              |
	 *    +-----------------------------------+
	 *    |                ...                |
	 *    +-----------------------------------+
	 *    |                ...                |
	 *    +-----------------+-----------------+
	 *    |    ... MAC      |
	 *    +-----------------+
	 */
	if(o.tcp.auth){
		*checksum++ = TCPOPT_AO;
		*checksum++ = TCPOLEN_AO;
		*checksum++ = __8BIT_RND(o.tcp.key_id);
		*checksum++ = __8BIT_RND(o.tcp.next_key);
		/*
		 * The Authentication key uses HMAC-MD5 digest.
		 */
		for(counter = 0 ; counter < auth_hmac_md5_len(o.tcp.auth) ; counter++)
			*checksum++ = __8BIT_RND(0);
	}
	/* Padding the TCP Options. */
	for( ; tcpolen & 3 ; tcpolen++)
		*checksum++ = o.tcp.nop;
	/* Computing the Checksum offset. */
	offset += tcpolen;

	/* PSEUDO Header structure making a pointer to Checksum. */
	pseudo           = (struct psdhdr *)(checksum);
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
	tcp->check   = o.bogus_csum ? \
		               __16BIT_RND(0) : \
	               cksum((u_int16_t *)tcp, offset);

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
#endif  /* TCP_C__ */
