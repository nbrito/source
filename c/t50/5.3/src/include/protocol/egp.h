/* 
 * $Id: egp.h,v 5.3 2011-03-09 19:32:20-03 nbrito Exp $
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
#ifndef __EGP_H
#define __EGP_H 1


/* GLOBAL HEADERS/INCLUDES

   Global headers/includes used by code.
   Any new global headers/includes should be added in this section. */
#include <common.h>


#ifdef __cplusplus
extern "C" {
#endif


__BEGIN_DECLS


/* GLOBAL EGP PROTOCOL DEFINITIONS

   Global EGP protocol definitions used by code.
   Any new global EGP protocol definition should be added in this section. */
#ifdef  EGPVERSION
#	warning "Sorry! The t50 is disabling EGPVERSION!"
#	undef  EGPVERSION
#	define EGPVERSION             2
#else   /* EGPVERSION */
#	define EGPVERSION             2
#endif  /* EGPVERSION */
/* EGP Message Types */
enum egp_type{
	EGP_NEIGHBOR_UPDATE_RESP    = 1,
#define EGP_NEIGHBOR_UPDATE_RESP      EGP_NEIGHBOR_UPDATE_RESP
	EGP_NEIGHBOR_POLL_COMMAND,
#define EGP_NEIGHBOR_POLL_COMMAND     EGP_NEIGHBOR_POLL_COMMAND
	EGP_NEIGHBOR_ACQUISITION,
#define EGP_NEIGHBOR_ACQUISITION      EGP_NEIGHBOR_ACQUISITION
	EGP_NEIGHBOR_REACHABILITY   = 5,
#define EGP_NEIGHBOR_REACHABILITY     EGP_NEIGHBOR_REACHABILITY
	EGP_NEIGHBOR_ERROR_RESP     = 8
#define EGP_NEIGHBOR_ERROR_RESP       EGP_NEIGHBOR_ERROR_RESP
};
/* EGP Message Neighbor Acquisition Codes */
enum acquisition_code{
	EGP_ACQ_CODE_REQUEST_CMD    = 0,
#define EGP_ACQ_CODE_REQUEST_CMD      EGP_ACQ_CODE_REQUEST_CMD
	EGP_ACQ_CODE_CONFIRM_RESP,
#define EGP_ACQ_CODE_CONFIRM_RESP     EGP_ACQ_CODE_CONFIRM_RESP
	EGP_ACQ_CODE_REFUSE_RESP,
#define EGP_ACQ_CODE_REFUSE_RESP      EGP_ACQ_CODE_REFUSE_RESP
	EGP_ACQ_CODE_CEASE_CMD,
#define EGP_ACQ_CODE_CEASE_CMD        EGP_ACQ_CODE_CEASE_CMD
	EGP_ACQ_CODE_CEASE_ACKCMD,
#define EGP_ACQ_CODE_CEASE_ACKCMD     EGP_ACQ_CODE_CEASE_ACKCMD

};
/* EGP Message Neighbor Acquisition Type */
enum egp_acq_status{
	EGP_ACQ_STAT_UNSPECIFIED    = 0,
#define EGP_ACQ_STAT_UNSPECIFIED      EGP_ACQ_STAT_UNSPECIFIED
	EGP_ACQ_STAT_ACTIVE_MODE,
#define EGP_ACQ_STAT_ACTIVE_MODE      EGP_ACQ_STAT_ACTIVE_MODE
	EGP_ACQ_STAT_PASSIVE_MODE,
#define EGP_ACQ_STAT_PASSIVE_MODE     EGP_ACQ_STAT_PASSIVE_MODE
	EGP_ACQ_STAT_INSUFFICIENT,
#define EGP_ACQ_STAT_INSUFFICIENT     EGP_ACQ_STAT_INSUFFICIENT
	EGP_ACQ_STAT_ADM_PROHIBIT,
#define EGP_ACQ_STAT_ADM_PROHIBIT     EGP_ACQ_STAT_ADM_PROHIBIT
	EGP_ACQ_STAT_GOING_DOWN,
#define EGP_ACQ_STAT_GOING_DOWN       EGP_ACQ_STAT_GOING_DOWN
	EGP_ACQ_STAT_PARAMETER,
#define EGP_ACQ_STAT_PARAMETER        EGP_ACQ_STAT_PARAMETER
	EGP_ACQ_STAT_VIOLATION,
#define EGP_ACQ_STAT_VIOLATION        EGP_ACQ_STAT_VIOLATION
};


/* EGP PROTOCOL STRUCTURES

   EGP protocol structures used by code.
   Any new EGP protocol structure should be added in this section. */
/*
 * Exterior Gateway Protocol (EGP) Formal Specification (RFC 904)
 *
 * Appendix A.  EGP Message Formats
 *
 *      The  formats  for  the  various  EGP messages are described in this
 * section.  All  EGP  messages  include  a ten-octet header of six fields,
 * which may  be followed  by  additional fields depending on message type.
 * The format of the  header is shown below along with a description of its
 * fields.
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | EGP Version # |     Type      |     Code      |    Status     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Checksum               |       Autonomous System #     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Sequence #             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * EGP Version #           assigned number identifying the EGP version
 *                         (currently 2)
 *
 * Type                    identifies the message type
 *
 * Code                    identifies the message code (subtype)
 *
 * Status                  contains message-dependent status information
 *
 * Checksum                The EGP checksum  is the 16-bit one's complement
 *                         of the one's  complement sum  of the EGP message
 *                         starting with the EGP version number field. When
 *                         computing the checksum the checksum field itself
 *                         should be zero.
 *
 * Autonomous System #     assigned   number   identifying  the  particular
 *                         autonomous system
 * 
 * Sequence #              send state variable (commands) or  receive state
 *                         variable (responses and indications)
 */
struct egp_hdr{
	u_int8_t  version;                /* version                     */
	u_int8_t  type;                   /* type                        */
	u_int8_t  code;                   /* code                        */
	u_int8_t  status;                 /* status                      */
	u_int16_t check;                  /* checksum                    */
	u_int16_t as;                     /* autonomous system           */
	u_int16_t sequence;               /* sequence number             */
	u_int8_t  __data[0];              /* data                        */
};
/*
 * Exterior Gateway Protocol (EGP) Formal Specification (RFC 904)
 *
 * A.1.  Neighbor Acquisition Messages
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | EGP Version # |     Type      |     Code      |    Status     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Checksum               |       Autonomous System #     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Sequence #             |          Hello Interval       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Poll Interval          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Note:  the Hello Interval and Poll Interval fields are present  only  in
 * Request and Confirm messages.
 *
 * Type                    3
 *
 * Code                    0       Request command
 *                         1       Confirm response
 *                         2       Refuse response
 *                         3       Cease command
 *                         4       Cease-ack response
 *
 * Status (see below)      0       unspecified
 *                         1       active mode
 *                         2       passive mode
 *                         3       insufficient resources
 *                         4       administratively prohibited
 *                         5       going down
 *                         6       parameter problem
 *                         7       protocol violation
 *
 * Hello Interval          minimum Hello command polling interval (seconds)
 *
 * Poll Interval           minimum Poll command polling interval (seconds)
 */
struct egp_acq_hdr{
	__be16	  hello;                  /* hello interval              */
	__be16	  poll;                   /* poll interval               */
};


__END_DECLS


#ifdef __cplusplus
}
#endif


#endif  /* __EGP_H */
