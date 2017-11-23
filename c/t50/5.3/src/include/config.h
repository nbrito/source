/* 
 * $Id: config.h,v 5.9 2011-03-11 14:30:32-03 nbrito Exp $
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
#ifndef __CONFIG_H
#define __CONFIG_H 1


/* GLOBAL HEADERS/INCLUDES

   Global headers/includes used by code.
   Any new global headers/includes should be added in this section. */
#include <common.h>


#ifdef __cplusplus
extern "C" {
#endif


__BEGIN_DECLS


/* GLOBAL CONFIG DEFINITIONS

   Global config definitions used by code.
   Any new global config definition should be added in this section. */
/* Command line interface options which do not have short options. */
enum {
	/* XXX COMMON OPTIONS                            */
	OPTION_THRESHOLD = 128,
	OPTION_FLOOD,
	OPTION_ENCAPSULATED,
#ifdef  __HAVE_TURBO__
	OPTION_TURBO,
#endif  /* __HAVE_TURBO__ */
	OPTION_COPYRIGHT,
#ifdef __HAVE_USAGE__
	OPTION_LIST_PROTOCOL,
#endif /* __HAVE_USAGE__ */
	/* XXX DCCP, TCP & UDP HEADER OPTIONS            */
	OPTION_SOURCE,
	OPTION_DESTINATION,
	/* XXX IP HEADER OPTIONS  (IPPROTO_IP = 0)       */
	OPTION_IP_TOS,
	OPTION_IP_ID,
	OPTION_IP_OFFSET,
	OPTION_IP_TTL,
	OPTION_IP_PROTOCOL,
	/* XXX GRE HEADER OPTIONS (IPPROTO_GRE = 47)     */
	OPTION_GRE_SEQUENCE_PRESENT,
	OPTION_GRE_KEY_PRESENT,
	OPTION_GRE_CHECKSUM_PRESENT,
	OPTION_GRE_KEY,
	OPTION_GRE_SEQUENCE,
	OPTION_GRE_SADDR,
	OPTION_GRE_DADDR,
	/* XXX ICMP HEADER OPTIONS (IPPROTO_ICMP = 1)    */
	OPTION_ICMP_TYPE,
	OPTION_ICMP_CODE,
	OPTION_ICMP_GATEWAY,
	OPTION_ICMP_ID,
	OPTION_ICMP_SEQUENCE,
	/* XXX IGMP HEADER OPTIONS (IPPROTO_IGMP = 2)    */
	OPTION_IGMP_TYPE,
	OPTION_IGMP_CODE,
	OPTION_IGMP_GROUP,
	OPTION_IGMP_QRV,
	OPTION_IGMP_SUPPRESS,
	OPTION_IGMP_QQIC,
	OPTION_IGMP_GREC_TYPE,
	OPTION_IGMP_SOURCES,
	OPTION_IGMP_GREC_MULTICAST,
	OPTION_IGMP_ADDRESS,
	/* XXX TCP HEADER OPTIONS (IPPROTO_TCP = 6)      */
	OPTION_TCP_ACKNOWLEDGE,
	OPTION_TCP_SEQUENCE,
	OPTION_TCP_OFFSET,
	OPTION_TCP_URGENT_POINTER,
	OPTION_TCP_MSS,
	OPTION_TCP_WSOPT,
	OPTION_TCP_TSOPT,
	OPTION_TCP_SACK_OK,
	OPTION_TCP_CC,
	OPTION_TCP_CC_NEW,
	OPTION_TCP_CC_ECHO,
	OPTION_TCP_SACK_EDGE,
	OPTION_TCP_MD5_SIGNATURE,
	OPTION_TCP_AUTHENTICATION,
	OPTION_TCP_AUTH_KEY_ID,
	OPTION_TCP_AUTH_NEXT_KEY,
	OPTION_TCP_NOP,
	/* XXX EGP HEADER OPTIONS (IPPROTO_EGP = 8)      */
	OPTION_EGP_TYPE,
	OPTION_EGP_CODE,
	OPTION_EGP_STATUS,
	OPTION_EGP_AS,
	OPTION_EGP_SEQUENCE,
	OPTION_EGP_HELLO,
	OPTION_EGP_POLL,
	/* XXX RIP HEADER OPTIONS (IPPROTO_UDP = 17)     */
	OPTION_RIP_COMMAND,
	OPTION_RIP_FAMILY,
	OPTION_RIP_ADDRESS,
	OPTION_RIP_METRIC,
	OPTION_RIP_DOMAIN,
	OPTION_RIP_TAG,
	OPTION_RIP_NETMASK,
	OPTION_RIP_NEXTHOP,
	OPTION_RIP_AUTHENTICATION,
	OPTION_RIP_AUTH_KEY_ID,
	OPTION_RIP_AUTH_SEQUENCE,
	/* XXX DCCP HEADER OPTIONS (IPPROTO_DCCP = 33)   */
	OPTION_DCCP_OFFSET,
	OPTION_DCCP_CSCOV,
	OPTION_DCCP_CCVAL,
	OPTION_DCCP_TYPE,
	OPTION_DCCP_EXTEND,
	OPTION_DCCP_SEQUENCE_01,
	OPTION_DCCP_SEQUENCE_02,
	OPTION_DCCP_SEQUENCE_03,
	OPTION_DCCP_SERVICE,
	OPTION_DCCP_ACKNOWLEDGE_01,
	OPTION_DCCP_ACKNOWLEDGE_02,
	OPTION_DCCP_RESET_CODE,
	/* XXX RSVP HEADER OPTIONS (IPPROTO_RSVP = 46)   */
	OPTION_RSVP_FLAGS,
	OPTION_RSVP_TYPE,
	OPTION_RSVP_TTL,
	OPTION_RSVP_SESSION_ADDRESS,
	OPTION_RSVP_SESSION_PROTOCOL,
	OPTION_RSVP_SESSION_FLAGS,
	OPTION_RSVP_SESSION_PORT,
	OPTION_RSVP_HOP_ADDRESS,
	OPTION_RSVP_HOP_IFACE,
	OPTION_RSVP_TIME_REFRESH,
	OPTION_RSVP_ERROR_ADDRESS,
	OPTION_RSVP_ERROR_FLAGS,
	OPTION_RSVP_ERROR_CODE,
	OPTION_RSVP_ERROR_VALUE,
	OPTION_RSVP_SCOPE,
	OPTION_RSVP_SCOPE_ADDRESS,
	OPTION_RSVP_STYLE_OPTION,
	OPTION_RSVP_SENDER_ADDRESS,
	OPTION_RSVP_SENDER_PORT,
	OPTION_RSVP_TSPEC_TRAFFIC,
	OPTION_RSVP_TSPEC_GUARANTEED,
	OPTION_RSVP_TSPEC_TOKEN_R,
	OPTION_RSVP_TSPEC_TOKEN_B,
	OPTION_RSVP_TSPEC_DATA_P,
	OPTION_RSVP_TSPEC_MINIMUM,
	OPTION_RSVP_TSPEC_MAXIMUM,
	OPTION_RSVP_ADSPEC_ISHOP,
	OPTION_RSVP_ADSPEC_PATH,
	OPTION_RSVP_ADSPEC_MINIMUM,
	OPTION_RSVP_ADSPEC_MTU,
	OPTION_RSVP_ADSPEC_GUARANTEED,
	OPTION_RSVP_ADSPEC_CONTROLLED,
	OPTION_RSVP_ADSPEC_CTOT,
	OPTION_RSVP_ADSPEC_DTOT,
	OPTION_RSVP_ADSPEC_CSUM,
	OPTION_RSVP_ADSPEC_DSUM,
	OPTION_RSVP_CONFIRM_ADDR,
	/* XXX IPSEC HEADER OPTIONS (IPPROTO_AH = 51 & IPPROTO_ESP = 50) */
	OPTION_IPSEC_AH_LENGTH,
	OPTION_IPSEC_AH_SPI,
	OPTION_IPSEC_AH_SEQUENCE,
	OPTION_IPSEC_ESP_SPI,
	OPTION_IPSEC_ESP_SEQUENCE,
	/* XXX EIGRP HEADER OPTIONS (IPPROTO_EIGRP = 88) */
	OPTION_EIGRP_OPCODE,
	OPTION_EIGRP_FLAGS,
	OPTION_EIGRP_SEQUENCE,
	OPTION_EIGRP_ACKNOWLEDGE,
	OPTION_EIGRP_AS,
	OPTION_EIGRP_TYPE,
	OPTION_EIGRP_LENGTH,
	OPTION_EIGRP_K1,
	OPTION_EIGRP_K2,
	OPTION_EIGRP_K3,
	OPTION_EIGRP_K4,
	OPTION_EIGRP_K5,
	OPTION_EIGRP_HOLD,
	OPTION_EIGRP_IOS_VERSION,
	OPTION_EIGRP_PROTO_VERSION,
	OPTION_EIGRP_NEXTHOP,
	OPTION_EIGRP_DELAY,
	OPTION_EIGRP_BANDWIDTH,
	OPTION_EIGRP_MTU,
	OPTION_EIGRP_HOP_COUNT,
	OPTION_EIGRP_LOAD,
	OPTION_EIGRP_RELIABILITY,
	OPTION_EIGRP_DESINATION,
	OPTION_EIGRP_SOURCE_ROUTER,
	OPTION_EIGRP_SOURCE_AS,
	OPTION_EIGRP_TAG,
	OPTION_EIGRP_METRIC,
	OPTION_EIGRP_ID,
	OPTION_EIGRP_EXTERNAL_FLAGS,
	OPTION_EIGRP_ADDRESS,
	OPTION_EIGRP_MULTICAST,
	OPTION_EIGRP_AUTHENTICATION,
	OPTION_EIGRP_AUTH_KEY_ID,
	/* XXX OSPF HEADER OPTIONS (IPPROTO_OSPF = 89)   */
	OPTION_OSPF_TYPE,
	OPTION_OSPF_LENGTH,
	OPTION_OSPF_ROUTER_ID,
	OPTION_OSPF_AREA_ID,
	OPTION_OSPF_NETMASK,
	OPTION_OSPF_HELLO_INTERVAL,
	OPTION_OSPF_HELLO_PRIORITY,
	OPTION_OSPF_HELLO_DEAD,
	OPTION_OSPF_HELLO_DESIGN,
	OPTION_OSPF_HELLO_BACKUP,
	OPTION_OSPF_HELLO_NEIGHBOR,
	OPTION_OSPF_HELLO_ADDRESS,
	OPTION_OSPF_DD_MTU,
	OPTION_OSPF_DD_MASTER_SLAVE,
	OPTION_OSPF_DD_MORE,
	OPTION_OSPF_DD_INIT,
	OPTION_OSPF_DD_OOBRESYNC,
	OPTION_OSPF_DD_SEQUENCE,
	OPTION_OSPF_DD_INCLUDE_LSA,
	OPTION_OSPF_LSA_AGE,
	OPTION_OSPF_LSA_DO_NOT_AGE,
	OPTION_OSPF_LSA_TYPE,
	OPTION_OSPF_LSA_LSID,
	OPTION_OSPF_LSA_ROUTER,
	OPTION_OSPF_LSA_SEQUENCE,
	OPTION_OSPF_LSA_METRIC,
	OPTION_OSPF_LSA_FLAG_BORDER,
	OPTION_OSPF_LSA_FLAG_EXTERNAL,
	OPTION_OSPF_LSA_FLAG_VIRTUAL,
	OPTION_OSPF_LSA_FLAG_WILD,
	OPTION_OSPF_LSA_FLAG_NSSA_TR,
	OPTION_OSPF_LSA_LINK_ID,
	OPTION_OSPF_LSA_LINK_DATA,
	OPTION_OSPF_LSA_LINK_TYPE,
	OPTION_OSPF_LSA_ATTACHED,
	OPTION_OSPF_LSA_LARGER,
	OPTION_OSPF_LSA_FORWARD,
	OPTION_OSPF_LSA_EXTERNAL,
	OPTION_OSPF_VERTEX_ROUTER,
	OPTION_OSPF_VERTEX_NETWORK,
	OPTION_OSPF_VERTEX_ID,
	OPTIONS_OSPF_LLS_OPTION_LR,
	OPTIONS_OSPF_LLS_OPTION_RS,
	OPTION_OSPF_AUTHENTICATION,
	OPTION_OSPF_AUTH_KEY_ID,
	OPTION_OSPF_AUTH_SEQUENCE,
};


/* CONFIG STRUCTURES

   Config structures used by code.
   Any new config structure should be added in this section. */
#ifdef  __HAVE_CIDR__
struct cidr{
	u_int32_t hostid;                 /* hosts identifiers           */
	in_addr_t __1st_addr;             /* first IP address            */
};
#endif  /* __HAVE_CIDR__ */
struct config_options{
	/* XXX COMMON OPTIONS                                            */
	u_int32_t threshold;              /* amount of packets           */
	u_int32_t flood;                  /* flood                       */
	u_int8_t  encapsulated:1;         /* GRE encapsulated            */
	u_int32_t bogus_csum;             /* bogus packet checksum       */
#ifdef  __HAVE_TURBO__
	u_int32_t turbo;                  /* duplicate the attack        */
#endif  /* __HAVE_TURBO__ */
	/* XXX DCCP, TCP & UDP HEADER OPTIONS                            */
	u_int16_t source;                 /* general source port         */
	u_int16_t dest;                   /* general destination port    */
#ifdef  __HAVE_CIDR__
	u_int32_t bits:5;                 /* CIDR bits                   */
#endif  /* __HAVE_CIDR__ */
	/* XXX IP HEADER OPTIONS  (IPPROTO_IP = 0)                       */
	struct{
		u_int8_t  tos;            /* type of service             */
		u_int16_t id;             /* identification              */
		u_int16_t frag_off;       /* fragmentation offset        */
		u_int8_t  ttl;            /* time to live                */
		u_int8_t  protocol;       /* packet protocol             */
		u_int32_t protoname;      /* protocol name               */
		in_addr_t saddr;          /* source address              */
		in_addr_t daddr;          /* destination address         */
	}ip;
	/* XXX GRE HEADER OPTIONS (IPPROTO_GRE = 47)                     */
	struct{
		u_int8_t  options;        /* GRE options bitmask         */
		u_int8_t  S:1;            /* sequence number present     */
		u_int8_t  K:1;            /* key present                 */
		u_int8_t  C:1;            /* checksum present            */
		u_int32_t key;            /* key                         */
		u_int32_t sequence;       /* sequence number             */
		in_addr_t saddr;          /* GRE source address          */
		in_addr_t daddr;          /* GRE destination address     */
	}gre;
	/* XXX ICMP HEADER OPTIONS (IPPROTO_ICMP = 1)                    */
	struct{
		u_int8_t  type;           /* type                        */
		u_int8_t  code;           /* code                        */
		u_int16_t id;             /* identification              */
		u_int16_t sequence;       /* sequence number             */
		in_addr_t gateway;        /* gateway address             */
	}icmp;
	/* XXX IGMP HEADER OPTIONS (IPPROTO_IGMP = 2)                    */
	struct{
		u_int8_t  type;           /* type                        */
		u_int8_t  code;           /* code                        */
		in_addr_t group;          /* group address               */
		u_int8_t  qrv:3,          /* querier robustness variable */
		          suppress:1;     /* suppress router-side        */
		u_int8_t  qqic;           /* querier query interv. code  */
		u_int8_t  grec_type;      /* group record type           */
		u_int8_t  sources;        /* number of sources           */
		in_addr_t grec_mca;       /* group record multicast addr */
		in_addr_t address[255];   /* source address(es)          */
	}igmp;
	/* XXX TCP HEADER OPTIONS (IPPROTO_TCP = 6)                      */
	struct{
		u_int32_t sequence;       /* initial sequence number     */
		u_int32_t acknowledge;    /* acknowledgment sequence     */
		u_int8_t  doff:4;         /* data offset                 */
		u_int8_t  fin:1;          /* end of data flag            */
		u_int8_t  syn:1;          /* synchronize ISN flag        */
		u_int8_t  rst:1;          /* reset connection flag       */
		u_int8_t  psh:1;          /* push flag                   */
		u_int8_t  ack:1;          /* acknowledgment # valid flag */
		u_int8_t  urg:1;          /* urgent pointer valid flag   */
		u_int8_t  ece:1;          /* ecn-echo                    */
		u_int8_t  cwr:1;          /* congestion windows reduced  */
		u_int16_t window;         /* window size                 */
		u_int16_t urg_ptr;        /* urgent pointer data         */
		u_int8_t  options;        /* TCP options bitmask         */
		u_int16_t mss;            /* MSS option        (RFC793)  */
		u_int8_t  wsopt;          /* WSOPT option      (RFC1323) */
		u_int32_t tsval;          /* TSval option      (RFC1323) */
		u_int32_t tsecr;          /* TSecr option      (RFC1323) */
		u_int32_t cc;             /* T/TCP CC          (RFC1644) */
		u_int32_t cc_new;         /* T/TCP CC.NEW      (RFC1644) */
		u_int32_t cc_echo;        /* T/TCP CC.ECHO     (RFC1644) */
		u_int32_t sack_left;      /* SACK-Left option  (RFC2018) */
		u_int32_t sack_right;     /* SACK-Right option (RFC2018) */
		u_int8_t  md5:1;          /* MD5 Option        (RFC2385) */
		u_int8_t  auth:1;         /* AO Option         (RFC5925) */
		u_int8_t  key_id;         /* AO key ID         (RFC5925) */
		u_int8_t  next_key;       /* AO next key ID    (RFC5925) */
		u_int8_t  nop;            /* NOP option        (RFC793)  */
	}tcp;
	/* XXX EGP HEADER OPTIONS (IPPROTO_EGP = 8)                      */
	struct{
		u_int8_t  type;           /* type                        */
		u_int8_t  code;           /* code                        */
		u_int8_t  status;         /* status                      */
		u_int16_t as;             /* autonomous system           */
		u_int16_t sequence;       /* sequence number             */
		u_int16_t hello;          /* hello interval              */
		u_int16_t poll;           /* poll interval               */
	}egp;
	/* XXX RIP HEADER OPTIONS (IPPROTO_UDP = 17)                     */
	struct{
		u_int8_t  command;        /* command                     */
		u_int16_t family;         /* address family identifier   */
		in_addr_t address;        /* IP address                  */
		u_int32_t metric;         /* metric                      */
		u_int16_t domain;         /* router domain               */
		u_int16_t tag;            /* router tag                  */
		in_addr_t netmask;        /* subnet mask                 */
		in_addr_t next_hop;       /* next hop                    */
		u_int8_t  auth:1;         /* authentication              */
		u_int8_t  key_id;         /* authentication key ID       */
		u_int32_t sequence;       /* authentication sequence     */
	}rip;
	/* XXX DCCP HEADER OPTIONS (IPPROTO_DCCP = 33)                   */
	struct{
		u_int8_t  doff;           /* data offset                 */
		u_int8_t  cscov:4;        /* checksum coverage           */
		u_int8_t  ccval:4;        /* HC-sender CCID              */
		u_int8_t  type:4;         /* DCCP type                   */
		u_int8_t  ext:1;          /* extend the sequence number  */
		u_int16_t sequence_01;    /* sequence number             */
		u_int8_t  sequence_02;    /* extended sequence number    */
		u_int32_t sequence_03;    /* low sequence number         */
		u_int32_t service;        /* service code                */
		u_int16_t acknowledge_01; /* acknowledgment # high       */
		u_int32_t acknowledge_02; /* acknowledgment # low        */
		u_int8_t  rst_code;       /* reset code                  */
	}dccp;
	/* XXX RSVP HEADER OPTIONS (IPPROTO_RSVP = 46)                   */
	struct{
		u_int8_t  flags:4;        /* flags                       */
		u_int8_t  type;           /* message type                */
		u_int8_t  ttl;            /* time to live                */
		in_addr_t session_addr;   /* SESSION destination address */
		u_int8_t  session_proto;  /* SESSION protocol ID         */
		u_int8_t  session_flags;  /* SESSION flags               */
		u_int16_t session_port;   /* SESSION destination port    */
		in_addr_t hop_addr;       /* RESV_HOP neighbor address   */
		u_int32_t hop_iface;      /* RESV_HOP logical interface  */
		u_int32_t time_refresh;   /* TIME refresh interval       */
		in_addr_t error_addr;     /* ERROR node address          */
		u_int8_t  error_flags:3;  /* ERROR flags                 */
		u_int8_t  error_code;     /* ERROR code                  */
		u_int16_t error_value;    /* ERROR value                 */
		u_int8_t  scope;          /* number of SCOPE(s)          */
		in_addr_t address[255];   /* SCOPE address(es)           */
		u_int32_t style_opt:24;   /* STYLE option vector         */
		in_addr_t sender_addr;    /* SENDER TEMPLATE address     */
		u_int16_t sender_port;    /* SENDER TEMPLATE port        */
		u_int8_t  tspec;          /* TSPEC services              */
		u_int32_t tspec_r;        /* TSPEC Token Bucket Rate     */
		u_int32_t tspec_b;        /* TSPEC Token Bucket Size     */
		u_int32_t tspec_p;        /* TSPEC Peak Data Rate        */
		u_int32_t tspec_m;        /* TSEPC Minimum Policed Unit  */
		u_int32_t tspec_M;        /* TSPEC Maximum Packet Size   */
		u_int32_t adspec_hop;     /* ADSPEC IS HOP cnt           */
		u_int32_t adspec_path;    /* ADSPEC Path b/w estimate    */
		u_int32_t adspec_minimum; /* ADSPEC Minimum Path Latency */
		u_int32_t adspec_mtu;     /* ADSPEC Composed MTU         */
		u_int8_t  adspec;         /* ADSPEC services             */
		u_int32_t adspec_Ctot;    /* ADSPEC ETE composed value C */
		u_int32_t adspec_Dtot;    /* ADSPEC ETE composed value D */
		u_int32_t adspec_Csum;    /* ADSPEC SLR point composed C */
		u_int32_t adspec_Dsum;    /* ADSPEC SLR point composed C */
		in_addr_t confirm_addr;   /* CONFIRM receiver address    */
	}rsvp;
	/* XXX IPSEC HEADER OPTIONS (IPPROTO_AH = 51 & IPPROTO_ESP = 50) */
	struct{
		u_int8_t  ah_length;      /* AH header length            */
		u_int32_t ah_spi;         /* AH SPI                      */
		u_int32_t ah_sequence;    /* AH sequence number          */
		u_int32_t esp_spi;        /* ESP SPI                     */
		u_int32_t esp_sequence;   /* ESP sequence number         */
	}ipsec;
	/* XXX EIGRP HEADER OPTIONS (IPPROTO_EIGRP = 88)                 */
	struct{
		u_int8_t  opcode;         /* opcode                      */
		u_int32_t flags;          /* flags                       */
		u_int32_t sequence;       /* sequence number             */
		u_int32_t acknowledge;    /* acknowledgment sequence #   */
		u_int32_t as;             /* autonomous system           */
		u_int16_t type;           /* type                        */
		u_int16_t length;         /* length                      */
		u_int8_t  values;         /* EIGRP K values bitmask      */
		u_int8_t  k1;             /* K1 value                    */
		u_int8_t  k2;             /* K2 value                    */
		u_int8_t  k3;             /* K3 value                    */
		u_int8_t  k4;             /* K4 value                    */
		u_int8_t  k5;             /* K5 value                    */
		u_int16_t hold;           /* hold time                   */
		u_int8_t  ios_major;      /* IOS Major Version           */
		u_int8_t  ios_minor;      /* IOS Minor Version           */
		u_int8_t  ver_major;      /* EIGRP Major Version         */
		u_int8_t  ver_minor;      /* EIGRP Minor Version         */
		in_addr_t next_hop;       /* next hop address            */
		u_int32_t delay;          /* delay                       */
		u_int32_t bandwidth;      /* bandwidth                   */
		u_int32_t mtu:24;         /* maximum transmission unit   */
		u_int8_t  hop_count;      /* hop count                   */
		u_int8_t  load;           /* load                        */
		u_int8_t  reliability;    /* reliability                 */
		u_int8_t  prefix:5;       /* subnet prefix - aka CIDR    */
		in_addr_t dest;           /* destination address         */
		in_addr_t src_router;     /* originating router          */
		u_int32_t src_as;         /* originating autonomous sys  */
		u_int32_t tag;            /* arbitrary tag               */
		u_int32_t proto_metric;   /* external protocol metric    */
		u_int8_t  proto_id;       /* external protocol ID        */
		u_int8_t  ext_flags;      /* external flags              */
		in_addr_t address;        /* IP address sequence         */
		u_int32_t multicast;      /* multicast sequence          */
		u_int8_t  auth:1;         /* authentication              */
		u_int32_t key_id;         /* authentication key ID       */
	}eigrp;
	/* XXX OSPF HEADER OPTIONS (IPPROTO_OSPF = 89)                   */
	struct{
		u_int8_t  type;           /* type                        */
		u_int16_t length;         /* length                      */
		in_addr_t rid;            /* router ID                   */
		in_addr_t aid;            /* area ID                     */
		u_int8_t  AID:1;          /* area ID present             */
		u_int8_t  options;        /* options                     */
		in_addr_t netmask;        /* subnet mask                 */
		u_int16_t hello_interval; /* HELLO interval              */
		u_int8_t  hello_priority; /* HELLO router priority       */
		u_int32_t hello_dead;     /* HELLO router dead interval  */
		in_addr_t hello_design;   /* HELLO designated router     */
		in_addr_t hello_backup;   /* HELLO backup designated     */
		u_int8_t  neighbor;       /* HELLO number of neighbors   */
		in_addr_t address[255];   /* HELLO neighbor address(es)  */
		u_int16_t dd_mtu;         /* DD MTU                      */ 
		u_int8_t  dd_dbdesc;      /* DD DB description           */
		u_int32_t dd_sequence;    /* DD sequence number          */
		u_int8_t  dd_include_lsa; /* DD LSA Header               */
		u_int16_t lsa_age;        /* LSA age                     */
		u_int8_t  lsa_dage:1;     /* LSA do not age              */
		u_int8_t  lsa_type;       /* LSA header type             */
		in_addr_t lsa_lsid;       /* LSA ID                      */
		in_addr_t lsa_router;     /* LSA advertising router      */
		u_int32_t lsa_sequence;   /* LSA sequence number         */
		u_int32_t lsa_metric:24;  /* LSA metric                  */
		u_int8_t  lsa_flags;      /* Router-LSA flags            */
		in_addr_t lsa_link_id;    /* Router-LSA link ID          */
		in_addr_t lsa_link_data;  /* Router-LSA link data        */
		u_int8_t  lsa_link_type;  /* Router-LSA link type        */
		in_addr_t lsa_attached;   /* Network-LSA attached router */
		u_int8_t  lsa_larger:1;   /* ASBR/NSSA-LSA ext. larger   */
		in_addr_t lsa_forward;    /* ASBR/NSSA-LSA forward       */
		in_addr_t lsa_external;   /* ASBR/NSSA-LSA external      */
		u_int32_t vertex_type;    /* Group-LSA vertex type       */
		in_addr_t vertex_id;      /* Group-LSA vertex ID         */
		u_int32_t lls_options;    /* LSS Extended TLV options    */
		u_int8_t  auth:1;         /* authentication              */
		u_int8_t  key_id;         /* authentication key ID       */
		u_int32_t sequence;       /* authentication sequence     */
	}ospf;
};


__END_DECLS


#ifdef __cplusplus
}
#endif


#endif  /* __CONFIG_H */
