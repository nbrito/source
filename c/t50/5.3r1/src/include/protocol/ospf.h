/* 
 * $Id: ospf.h,v 5.3 2011-03-09 19:32:20-03 nbrito Exp $
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
#ifndef __OSPF_H
#define __OSPF_H 1


/* GLOBAL HEADERS/INCLUDES

   Global headers/includes used by code.
   Any new global headers/includes should be added in this section. */
#include <common.h>


#ifdef __cplusplus
extern "C" {
#endif


__BEGIN_DECLS


/* GLOBAL OSPF PROTOCOL DEFINITIONS

   Global OSPF protocol definitions used by code.
   Any new global OSPF protocol definition should be added in this section. */
#ifdef  IPPROTO_OSPF
#	warning "Sorry! The t50 is disabling IPPROTO_OSPF!"
#	undef  IPPROTO_OSPF
#	define IPPROTO_OSPF           89
#else   /* IPPROTO_OSPF */
#	define IPPROTO_OSPF           89
#endif  /* IPPROTO_OSPF */
#ifdef  OSPFVERSION
#	warning "Sorry! The t50 is disabling OSPFVERSION!"
#	undef  OSPFVERSION
#	define OSPFVERSION            2
#else   /* OSPFVERSION */
#	define OSPFVERSION            2
#endif  /* OSPFVERSION */
/* OSPF Message Type */
enum ospf_type{
	OSPF_TYPE_HELLO             = 1,
#define OSPF_TYPE_HELLO               OSPF_TYPE_HELLO
#ifdef  OSPF_TLEN_HELLO
#	warning "Sorry! The t50 is disabling OSPF_TLEN_HELLO!"
#	undef  OSPF_TLEN_HELLO
#	define OSPF_TLEN_HELLO        20
#else   /* OSPF_TLEN_HELLO */
#	define OSPF_TLEN_HELLO        20
#endif  /* OSPF_TLEN_HELLO */
#ifdef  OSPF_TLEN_NEIGHBOR
#	warning "Sorry! The t50 is disabling OSPF_TLEN_NEIGHBOR!"
#	undef  OSPF_TLEN_NEIGHBOR
#	define OSPF_TLEN_NEIGHBOR(foo) \
			(foo * sizeof(in_addr_t))
#else   /* OSPF_TLEN_NEIGHBOR */
#	define OSPF_TLEN_NEIGHBOR(foo) \
			(foo * sizeof(in_addr_t))
#endif  /* OSPF_TLEN_NEIGHBOR */
	OSPF_TYPE_DD,
#define OSPF_TYPE_DD                  OSPF_TYPE_DD
#ifdef  OSPF_TLEN_DD
#	warning "Sorry! The t50 is disabling OSPF_TLEN_DD!"
#	undef  OSPF_TLEN_DD
#	define OSPF_TLEN_DD           8
#else   /* OSPF_TLEN_DD */
#	define OSPF_TLEN_DD           8
#endif  /* OSPF_TLEN_DD */
	OSPF_TYPE_LSREQUEST,
#define OSPF_TYPE_LSREQUEST    OSPF_TYPE_LSREQUEST
#ifdef  OSPF_TLEN_LSREQUEST
#	warning "Sorry! The t50 is disabling OSPF_TLEN_LSREQUEST!"
#	undef  OSPF_TLEN_LSREQUEST
#	define OSPF_TLEN_LSREQUEST    12
#else   /* OSPF_TLEN_LSREQUEST */
#	define OSPF_TLEN_LSREQUEST    12
#endif  /* OSPF_TLEN_LSREQUEST */
	OSPF_TYPE_LSUPDATE,
#define OSPF_TYPE_LSUPDATE            OSPF_TYPE_LSUPDATE
#ifdef  OSPF_TLEN_LSUPDATE
#	warning "Sorry! The t50 is disabling OSPF_TLEN_LSUPDATE!"
#	undef  OSPF_TLEN_LSUPDATE
#	define OSPF_TLEN_LSUPDATE     4
#else   /* OSPF_TLEN_LSUPDATE */
#	define OSPF_TLEN_LSUPDATE     4
#endif  /* OSPF_TLEN_LSUPDATE */
	OSPF_TYPE_LSACK,
#define OSPF_TYPE_LSACK               OSPF_TYPE_LSACK
};
/* OSPF HELLO, DD and LSA Option */
enum ospf_option{
	OSPF_OPTION_TOS             = 0x01,
#define OSPF_OPTION_TOS               OSPF_OPTION_TOS
	OSPF_OPTION_EXTERNAL        = 0x02,
#define OSPF_OPTION_EXTERNAL          OSPF_OPTION_EXTERNAL
	OSPF_OPTION_MULTICAST       = 0x04,
#define OSPF_OPTION_MULTICAST         OSPF_OPTION_MULTICAST
	OSPF_OPTION_NSSA            = 0x08,
#define OSPF_OPTION_NSSA              OSPF_OPTION_NSSA
	OSPF_OPTION_LLS             = 0x10,
#define OSPF_OPTION_LLS               OSPF_OPTION_LLS
	OSPF_OPTION_DEMAND          = 0x20,
#define OSPF_OPTION_DEMAND            OSPF_OPTION_DEMAND
	OSPF_OPTION_OPAQUE          = 0x40,
#define OSPF_OPTION_OPAQUE            OSPF_OPTION_OPAQUE
	OSPF_OPTION_DOWN            = 0x80,
#define OSPF_OPTION_DOWN              OSPF_OPTION_DOWN
};
/* OSPF DD DB Description */
enum dd_dbdesc{
	DD_DBDESC_MSLAVE            = 0x01,
#define DD_DBDESC_MSLAVE              DD_DBDESC_MSLAVE
	DD_DBDESC_MORE              = 0x02,
#define DD_DBDESC_MORE                DD_DBDESC_MORE
	DD_DBDESC_INIT              = 0x04,
#define DD_DBDESC_INIT                DD_DBDESC_INIT
	DD_DBDESC_OOBRESYNC         = 0x08,
#define DD_DBDESC_OOBRESYNC           DD_DBDESC_OOBRESYNC
};
/* OSPF LSA LS Type */
enum lsa_type{
#ifdef  LSA_TLEN_GENERIC
#	warning "Sorry! The t50 is disabling LSA_TLEN_GENERIC!"
#	undef  LSA_TLEN_GENERIC
#	define LSA_TLEN_GENERIC(foo) \
			(sizeof(struct ospf_lsa_hdr) + \
			(foo * sizeof(u_int32_t)))
#else   /* LSA_TLEN_GENERIC */
#	define LSA_TLEN_GENERIC(foo) \
			(sizeof(struct ospf_lsa_hdr) + \
			(foo * sizeof(u_int32_t)))
#endif  /* LSA_TLEN_GENERIC */
	LSA_TYPE_ROUTER             = 1,
#define LSA_TYPE_ROUTER               LSA_TYPE_ROUTER
#ifdef  LSA_TLEN_ROUTER
#	warning "Sorry! The t50 is disabling LSA_TLEN_ROUTER!"
#	undef  LSA_TLEN_ROUTER
#	define LSA_TLEN_ROUTER        LSA_TLEN_GENERIC(4)
#else   /* LSA_TLEN_ROUTER */
#	define LSA_TLEN_ROUTER        LSA_TLEN_GENERIC(4)
#endif  /* LSA_TLEN_ROUTER */
	LSA_TYPE_NETWORK,
#define LSA_TYPE_NETWORK              LSA_TYPE_NETWORK
#ifdef  LSA_TLEN_NETWORK
#	warning "Sorry! The t50 is disabling LSA_TLEN_NETWORK!"
#	undef  LSA_TLEN_NETWORK
#	define LSA_TLEN_NETWORK       LSA_TLEN_GENERIC(2)
#else   /* LSA_TLEN_NETWORK */
#	define LSA_TLEN_NETWORK       LSA_TLEN_GENERIC(2)
#endif  /* LSA_TLEN_NETWORK */
	LSA_TYPE_SUMMARY_IP,
#define LSA_TYPE_SUMMARY_IP           LSA_TYPE_SUMMARY_IP
	LSA_TYPE_SUMMARY_AS,
#define LSA_TYPE_SUMMARY_AS           LSA_TYPE_SUMMARY_AS
#ifdef  LSA_TLEN_SUMMARY
#	warning "Sorry! The t50 is disabling LSA_TLEN_SUMMARY!"
#	undef  LSA_TLEN_SUMMARY
#	define LSA_TLEN_SUMMARY       LSA_TLEN_GENERIC(2)
#else   /* LSA_TLEN_SUMMARY */
#	define LSA_TLEN_SUMMARY       LSA_TLEN_GENERIC(2)
#endif  /* LSA_TLEN_SUMMARY */
	LSA_TYPE_ASBR,
#define LSA_TYPE_ASBR                 LSA_TYPE_ASBR
#ifdef  LSA_TLEN_ASBR
#	warning "Sorry! The t50 is disabling LSA_TLEN_ASBR!"
#	undef  LSA_TLEN_ASBR
#	define LSA_TLEN_ASBR          LSA_TLEN_GENERIC(4)
#else   /* LSA_TLEN_ASBR */
#	define LSA_TLEN_ASBR          LSA_TLEN_GENERIC(4)
#endif  /* LSA_TLEN_ASBR */
	LSA_TYPE_MULTICAST,
#define LSA_TYPE_MULTICAST            LSA_TYPE_MULTICAST
#ifdef  LSA_TLEN_MULTICAST
#	warning "Sorry! The t50 is disabling LSA_TLEN_MULTICAST!"
#	undef  LSA_TLEN_MULTICAST
#	define LSA_TLEN_MULTICAST     LSA_TLEN_GENERIC(2)
#else   /* LSA_TLEN_MULTICAST */
#	define LSA_TLEN_MULTICAST     LSA_TLEN_GENERIC(2)
#endif  /* LSA_TLEN_MULTICAST */
	LSA_TYPE_NSSA,
#define LSA_TYPE_NSSA                 LSA_TYPE_NSSA
#ifdef  LSA_TLEN_NSSA
#	warning "Sorry! The t50 is disabling LSA_TLEN_NSSA!"
#	undef  LSA_TLEN_NSSA
#	define LSA_TLEN_NSSA          LSA_TLEN_ASBR
#else   /* LSA_TLEN_NSSA */
#	define LSA_TLEN_NSSA          LSA_TLEN_ASBR
#endif  /* LSA_TLEN_NSSA */
	LSA_TYPE_OPAQUE_LINK        = 9,
#define LSA_TYPE_OPAQUE_LINK          LSA_TYPE_OPAQUE_LINK

	LSA_TYPE_OPAQUE_AREA,
#define LSA_TYPE_OPAQUE_AREA          LSA_TYPE_OPAQUE_AREA
	LSA_TYPE_OPAQUE_FLOOD,
#define LSA_TYPE_OPAQUE_FLOOD         LSA_TYPE_OPAQUE_FLOOD
};
/* OSPF Router-LSA Flag */
enum router_flag{
	ROUTER_FLAG_BORDER          = 0x01,
#define ROUTER_FLAG_BORDER            ROUTER_FLAG_BORDER
	ROUTER_FLAG_EXTERNAL        = 0x02,
#define ROUTER_FLAG_EXTERNAL          ROUTER_FLAG_EXTERNAL
	ROUTER_FLAG_VIRTUAL         = 0x04,
#define ROUTER_FLAG_VIRTUAL           ROUTER_FLAG_VIRTUAL
	ROUTER_FLAG_WILD            = 0x08,
#define ROUTER_FLAG_WILD              ROUTER_FLAG_WILD
	ROUTER_FLAG_NSSA_TR         = 0x10,
#define ROUTER_FLAG_NSSA_TR           ROUTER_FLAG_NSSA_TR
};
/* OSPF Router-LSA Link type */
enum link_type{
	LINK_TYPE_PTP               = 1,
#define LINK_TYPE_PTP                 LINK_TYPE_PTP
	LINK_TYPE_TRANSIT,
#define LINK_TYPE_TRANSIT             LINK_TYPE_TRANSIT
	LINK_TYPE_STUB,
#define LINK_TYPE_STUB                LINK_TYPE_STUB
	LINK_TYPE_VIRTUAL,
#define LINK_TYPE_VIRTUAL             LINK_TYPE_VIRTUAL
};
/* OSPF Group-LSA Type */
enum vertex_type{
	VERTEX_TYPE_ROUTER          = 0x00000001,
#define VERTEX_TYPE_ROUTER            VERTEX_TYPE_ROUTER
	VERTEX_TYPE_NETWORK,
#define VERTEX_TYPE_NETWORK           VERTEX_TYPE_NETWORK
};
#ifdef  OSPF_TLV_HEADER
#	warning "Sorry! The t50 is disabling OSPF_TLV_HEADER!"
#	undef  OSPF_TLV_HEADER
#	define OSPF_TLV_HEADER        sizeof(struct ospf_lls_hdr)
#else   /* OSPF_TLV_HEADER */
#	define OSPF_TLV_HEADER        sizeof(struct ospf_lls_hdr)
#endif  /* OSPF_TLV_HEADER */
/* OSPF LLS Type/Length/Value */
enum ospf_tlv{
	OSPF_TLV_RESERVED           = 0,
#define OSPF_TLV_RESERVED             OSPF_TLV_RESERVED
	OSPF_TLV_EXTENDED,
#define OSPF_TLV_EXTENDED             OSPF_TLV_EXTENDED
#ifdef  OSPF_LEN_EXTENDED
#	warning "Sorry! The t50 is disabling OSPF_LEN_EXTENDED!"
#	undef  OSPF_LEN_EXTENDED
#	define OSPF_LEN_EXTENDED      OSPF_TLV_HEADER
#else   /* OSPF_LEN_EXTENDED */
#	define OSPF_LEN_EXTENDED      OSPF_TLV_HEADER
#endif  /* OSPF_LEN_EXTENDED */
#ifdef  EXTENDED_OPTIONS_LR
#	warning "Sorry! The t50 is disabling EXTENDED_OPTIONS_LR!"
#	define EXTENDED_OPTIONS_LR    0x00000001
#else   /* EXTENDED_OPTIONS_LR */
#	define EXTENDED_OPTIONS_LR    0x00000001
#endif  /* EXTENDED_OPTIONS_LR */
#ifdef  EXTENDED_OPTIONS_RS
#	warning "Sorry! The t50 is disabling EXTENDED_OPTIONS_RS!"
#	define EXTENDED_OPTIONS_RS    0x00000002
#else   /* EXTENDED_OPTIONS_RS */
#	define EXTENDED_OPTIONS_RS    0x00000002
#endif  /* EXTENDED_OPTIONS_RS */
	OSPF_TLV_CRYPTO,
#define OSPF_TLV_CRYPTO               OSPF_TLV_CRYPTO
#ifdef  OSPF_LEN_CRYPTO
#	warning "Sorry! The t50 is disabling OSPF_LEN_CRYPTO!"
#	undef  OSPF_LEN_CRYPTO
#	define OSPF_LEN_CRYPTO \
		OSPF_TLV_HEADER + \
		AUTH_TLEN_HMACMD5
#else   /* OSPF_LEN_CRYPTO */
#	define OSPF_LEN_CRYPTO \
		OSPF_TLV_HEADER + \
		AUTH_TLEN_HMACMD5
#endif  /* OSPF_LEN_CRYPTO */
};
/* Calculating OSPF LLS Type/Length/Value length */
#ifdef  ospf_tlv_len
#	warning "Sorry! The t50 is disabling ospf_tlv_len!"
#	undef  ospf_tlv_len
#	define ospf_tlv_len(foo, bar, baz) \
			(foo == OSPF_TYPE_HELLO || \
			 foo == OSPF_TYPE_DD ? \
				(bar ? \
					OSPF_TLV_HEADER * 2 + \
					OSPF_LEN_EXTENDED   + \
					(baz ? \
						OSPF_TLV_HEADER + \
						OSPF_LEN_CRYPTO : \
					0) : \
				0) : \
			0)
#else   /* ospf_tlv_len */
#	define ospf_tlv_len(foo, bar, baz) \
			(foo == OSPF_TYPE_HELLO || \
			 foo == OSPF_TYPE_DD ? \
				(bar ? \
					OSPF_TLV_HEADER * 2 + \
					OSPF_LEN_EXTENDED   + \
					(baz ? \
						OSPF_TLV_HEADER + \
						OSPF_LEN_CRYPTO : \
					0) : \
				0) : \
			0)
#endif  /* ospf_tlv_len */


/* OSPF PROTOCOL STRUCTURES

   OSPF protocol structures used by code.
   Any new OSPF protocol structure should be added in this section. */
/*
 * OSPF Version 2 (RFC 2328)
 *
 * A.3.1 The OSPF packet header
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Version #   |     Type      |         Packet length         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |	                       Router ID                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           Area ID                             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Checksum            |             AuType            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_hdr{
	u_int16_t version:8,              /* version                     */
	          type:8;                 /* type                        */
	u_int16_t length;                 /* length                      */
	in_addr_t rid;                    /* router ID                   */
	in_addr_t aid;                    /* area ID                     */
	u_int16_t check;                  /* checksum                    */
	u_int16_t autype;                 /* authentication type         */
	u_int8_t  __ospf_auth[0];         /* authentication header       */
	u_int8_t  __ospf_type_hdr[0];     /* type header                 */
};
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
struct ospf_auth_hdr{
	u_int16_t reserved;               /* reserved must be zero       */
	u_int16_t key_id:8,               /* authentication key ID       */
	          length:8;               /* authentication length       */
	u_int32_t sequence;               /* authentication sequence #   */
};
/*
 * OSPF Version 2 (RFC 2328)
 *
 * A.4.1 The Link State Advertisement (LSA) header
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            LS age             |    Options    |    LS type    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Link State ID                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     Advertising Router                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     LS sequence number                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         LS checksum           |             length            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_lsa_hdr{
	u_int16_t age;                    /* LSA age                     */
	u_int8_t  options;                /* LSA options                 */
	u_int8_t  type;                   /* LSA type                    */
	in_addr_t lsid;                   /* LSA link state ID           */
	in_addr_t router;                 /* LSA advertising router      */
	u_int32_t sequence;               /* LSA sequence number         */
	u_int16_t check;                  /* LSA checksum                */
	u_int16_t length;                 /* LSA length                  */
};
/*
 * OSPF Link-Local Signaling (RFC 5613)
 *
 * 2.2.  LLS Data Block
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            Checksum           |       LLS Data Length         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  |                           LLS TLVs                            |
 *  .                                                               .
 *  .                                                               .
 *  .                                                               .
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_lls_hdr{
	u_int16_t check;                  /* LLS checksum                */
	u_int16_t length;                 /* LLS length                  */
};


/* Function Name: OSPF header size calculation.

   Description:   This function calculates the size of OSPF header.

   Targets:       N/A */
__inline__ static size_t ospf_hdr_len(const u_int8_t foo, const u_int8_t bar, const u_int8_t baz, const u_int8_t qux){
	static size_t size;

	/*
	 * The code starts with size '0' and it accumulates all the required
	 * size if the conditionals match. Otherwise, it returns size '0'.
	 */
	size = 0;

	switch(foo){
		/*
		 * The size of a HELLO Message Type may vary based on the presence
		 * of neighbor address and the number of neighbor address(es).
		 */
		case OSPF_TYPE_HELLO:
			size += OSPF_TLEN_HELLO;
			size += OSPF_TLEN_NEIGHBOR(bar);
			break;
		/*
		 * The size of a Database Description (DD)  Message Type may vary 
		 * based on the presence of a LSA Header,  depending on the case,
		 * it may or may not be included.
		 */
		case OSPF_TYPE_DD:
			size += OSPF_TLEN_DD;
			size += (qux ? LSA_TLEN_GENERIC(0) : 0);
			break;
		case OSPF_TYPE_LSREQUEST:
			size += OSPF_TLEN_LSREQUEST;
			break;
		/*
		 * The size of a LS Update Message Type may vary based on the type
		 * of the LSA Header included in the message.
		 */
		case OSPF_TYPE_LSUPDATE:
			size += OSPF_TLEN_LSUPDATE;
			if(baz == LSA_TYPE_ROUTER)
				size += LSA_TLEN_ROUTER;
			else if(baz == LSA_TYPE_NETWORK)
				size += LSA_TLEN_NETWORK;
			else if(baz == LSA_TYPE_SUMMARY_IP ||
			        baz == LSA_TYPE_SUMMARY_AS)
				size += LSA_TLEN_SUMMARY;
			else if(baz == LSA_TYPE_ASBR)
				size += LSA_TLEN_ASBR;
			else if(baz == LSA_TYPE_MULTICAST)
				size += LSA_TLEN_MULTICAST;
			else if(baz == LSA_TYPE_NSSA)
				size += LSA_TLEN_NSSA;
			else
				size += LSA_TLEN_GENERIC(0);
			break;
		case OSPF_TYPE_LSACK:
			size += LSA_TLEN_GENERIC(0);
			break;
		default:
			break;
	}

	return(size);
}


__END_DECLS


#ifdef __cplusplus
}
#endif


#endif  /* __OSPF_H */
