/* 
 * $Id: usage.c,v 5.40 2011-03-21 15:09:30-03 nbrito Exp $
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
#ifndef USAGE_C__
#define USAGE_C__ 1

#include <common.h>


/* Function Name: Help and usage message.

   Description:   This function shows help and usage message.

   Targets:       N/A */
void usage(int8_t * program, int8_t * author, int8_t * email){
	fprintf(stdout, "T50 Experimental");
#ifdef  __HAVE_T50__
	fprintf(stdout, " Mixed ");
#else   /* __HAVE_T50__ */
	fprintf(stdout, " ");
#endif  /* __HAVE_T50__ */
	fprintf(stdout, "Packet Injector Tool [Version %s.%s", MAJOR_VERSION, MINOR_VERSION);
#ifdef  __HAVE_LIMITATION__
	fprintf(stdout, " + RFC1700/1918/3330]\n");
#else   /* __HAVE_LIMITATION__ */
	fprintf(stdout, "]\n");
#endif  /* __HAVE_LIMITATION__ */
	fprintf(stdout, "%s <%s>\n\n", author, email);
	fprintf(stdout, "Usage:  %s host", program);
#ifdef  __HAVE_CIDR__
	fprintf(stdout, "[/CIDR]");
#endif  /* __HAVE_CIDR__ */
	fprintf(stdout, " [options]\n\n");
#ifdef  __HAVE_USAGE__
	fprintf(stdout, "Common Options:\n");
	fprintf(stdout, "    --threshold NUM           Threshold of packets to send     (default 1,000)\n");
	fprintf(stdout, "    --flood                   This option supersedes the \'threshold\'\n");
	fprintf(stdout, "    --encapsulated            Encapsulated protocol (GRE)      (default OFF)\n");
	fprintf(stdout, " -B,--bogus-csum              Bogus checksum                   (default OFF)\n");
#ifdef  __HAVE_TURBO__
	fprintf(stdout, "    --turbo                   Extend the performance           (default OFF)\n");
#endif  /* __HAVE_TURBO__ */
	fprintf(stdout, "    --copyright               Display the copyright\n");
	fprintf(stdout, "    --list-protocol           Display the list of protocols supported by %s\n", program);
	fprintf(stdout, " -h,-?,--help                 Display this help and exit\n\n");
	fprintf(stdout, "GRE Options:\n");
	fprintf(stdout, "    --gre-seq-present         GRE sequence # present           (default OFF)\n");
	fprintf(stdout, "    --gre-key-present         GRE key present                  (default OFF)\n");
	fprintf(stdout, "    --gre-sum-present         GRE checksum present             (default OFF)\n");
	fprintf(stdout, "    --gre-key NUM             GRE key                          (default RANDOM)\n");
	fprintf(stdout, "    --gre-sequence NUM        GRE sequence #                   (default RANDOM)\n");
	fprintf(stdout, "    --gre-saddr ADDR          GRE IP source IP address         (default RANDOM)\n");
	fprintf(stdout, "    --gre-daddr ADDR          GRE IP destination IP address    (default RANDOM)\n\n");
	fprintf(stdout, "DCCP/TCP/UDP Options:\n");
	fprintf(stdout, "    --sport NUM               DCCP|TCP|UDP source port         (default RANDOM)\n");
	fprintf(stdout, "    --dport NUM               DCCP|TCP|UDP destination port    (default RANDOM)\n\n");
	fprintf(stdout, "IP Options:\n");
	fprintf(stdout, " -s,--saddr ADDR              IP source IP address             (default RANDOM)\n");
	fprintf(stdout, "    --tos NUM                 IP type of service               (default 0x%x)\n", IPTOS_PREC_IMMEDIATE);
	fprintf(stdout, "    --id NUM                  IP identification                (default RANDOM)\n");
	fprintf(stdout, "    --frag-offset NUM         IP fragmentation offset          (default 0)\n");
	fprintf(stdout, "    --ttl NUM                 IP time to live                  (default 255)\n");
	fprintf(stdout, "    --protocol PROTO          IP protocol                      (default TCP)\n\n");
	fprintf(stdout, "ICMP Options:\n");
	fprintf(stdout, "    --icmp-type NUM           ICMP type                        (default %d)\n", ICMP_ECHO);
	fprintf(stdout, "    --icmp-code NUM           ICMP code                        (default 0)\n");
	fprintf(stdout, "    --icmp-gateway ADDR       ICMP redirect gateway            (default RANDOM)\n");
	fprintf(stdout, "    --icmp-id NUM             ICMP identification              (default RANDOM)\n");
	fprintf(stdout, "    --icmp-sequence NUM       ICMP sequence #                  (default RANDOM)\n\n");
	fprintf(stdout, "IGMP Options:\n");
	fprintf(stdout, "    --igmp-type NUM           IGMPv1/v3 type                   (default 0x%x)\n", IGMP_HOST_MEMBERSHIP_QUERY);
	fprintf(stdout, "    --igmp-code NUM           IGMPv1/v3 code                   (default 0)\n");
	fprintf(stdout, "    --igmp-group ADDR         IGMPv1/v3 address                (default RANDOM)\n");
	fprintf(stdout, "    --igmp-qrv NUM            IGMPv3 QRV                       (default RANDOM)\n");
	fprintf(stdout, "    --igmp-suppress           IGMPv3 suppress router-side      (default OFF)\n");
	fprintf(stdout, "    --igmp-qqic NUM           IGMPv3 QQIC                      (default RANDOM)\n");
	fprintf(stdout, "    --igmp-grec-type NUM      IGMPv3 group record type         (default 1)\n");
	fprintf(stdout, "    --igmp-sources NUM        IGMPv3 # of sources              (default 2)\n");
	fprintf(stdout, "    --igmp-multicast ADDR     IGMPv3 group record multicast    (default RANDOM)\n");
	fprintf(stdout, "    --igmp-address ADDR,...   IGMPv3 source address(es)        (default RANDOM)\n\n");
	fprintf(stdout, "TCP Options:\n");
	fprintf(stdout, "    --acknowledge NUM         TCP ACK sequence #               (default RANDOM)\n");
	fprintf(stdout, "    --sequence NUM            TCP SYN sequence #               (default RANDOM)\n");
	fprintf(stdout, "    --data-offset NUM         TCP data offset                  (default %d)\n", (u_int32_t)(sizeof(struct tcphdr)/4));
	fprintf(stdout, " -F,--fin                     TCP FIN flag                     (default OFF)\n");
	fprintf(stdout, " -S,--syn                     TCP SYN flag                     (default OFF)\n");
	fprintf(stdout, " -R,--rst                     TCP RST flag                     (default OFF)\n");
	fprintf(stdout, " -P,--psh                     TCP PSH flag                     (default OFF)\n");
	fprintf(stdout, " -A,--ack                     TCP ACK flag                     (default OFF)\n");
	fprintf(stdout, " -U,--urg                     TCP URG flag                     (default OFF)\n");
	fprintf(stdout, " -E,--ece                     TCP ECE flag                     (default OFF)\n");
	fprintf(stdout, " -C,--cwr                     TCP CWR flag                     (default OFF)\n");
	fprintf(stdout, " -W,--window NUM              TCP Window size                  (default NONE)\n");
	fprintf(stdout, "    --urg-pointer NUM         TCP URG pointer                  (default NONE)\n");
	fprintf(stdout, "    --mss NUM                 TCP Maximum Segment Size         (default NONE)\n");
	fprintf(stdout, "    --wscale NUM              TCP Window Scale                 (default NONE)\n");
	fprintf(stdout, "    --tstamp NUM:NUM          TCP Timestamp (TSval:TSecr)      (default NONE)\n");
	fprintf(stdout, "    --sack-ok                 TCP SACK-Permitted               (default OFF)\n");
	fprintf(stdout, "    --ttcp-cc NUM             T/TCP Connection Count (CC)      (default NONE)\n");
	fprintf(stdout, "    --ccnew NUM               T/TCP Connection Count (CC.NEW)  (default NONE)\n");
	fprintf(stdout, "    --ccecho NUM              T/TCP Connection Count (CC.ECHO) (default NONE)\n");
	fprintf(stdout, "    --sack NUM:NUM            TCP SACK Edges (Left:Right)      (default NONE)\n");
	fprintf(stdout, "    --md5-signature           TCP MD5 signature included       (default OFF)\n");
	fprintf(stdout, "    --authentication          TCP-AO authentication included   (default OFF)\n");
	fprintf(stdout, "    --auth-key-id NUM         TCP-AO authentication key ID     (default 1)\n");
	fprintf(stdout, "    --auth-next-key NUM       TCP-AO authentication next key   (default 1)\n");
	fprintf(stdout, "    --nop                     TCP No-Operation                 (default EOL)\n\n");
	fprintf(stdout, "EGP Options:\n");
	fprintf(stdout, "    --egp-type NUM            EGP type                         (default %d)\n", EGP_NEIGHBOR_ACQUISITION);
	fprintf(stdout, "    --egp-code NUM            EGP code                         (default %d)\n", EGP_ACQ_CODE_CEASE_CMD);
	fprintf(stdout, "    --egp-status NUM          EGP status                       (default %d)\n", EGP_ACQ_STAT_ACTIVE_MODE);
	fprintf(stdout, "    --egp-as NUM              EGP autonomous system            (default RANDOM)\n");
	fprintf(stdout, "    --egp-sequence NUM        EGP sequence #                   (default RANDOM)\n");
	fprintf(stdout, "    --egp-hello NUM           EGP hello interval               (default RANDOM)\n");
	fprintf(stdout, "    --egp-poll NUM            EGP poll interval                (default RANDOM)\n\n");
	fprintf(stdout, "RIP Options:\n");
	fprintf(stdout, "    --rip-command NUM         RIPv1/v2 command                 (default 2)\n");
	fprintf(stdout, "    --rip-family NUM          RIPv1/v2 address family          (default %d)\n", AF_INET);
	fprintf(stdout, "    --rip-address ADDR        RIPv1/v2 router address          (default RANDOM)\n");
	fprintf(stdout, "    --rip-metric NUM          RIPv1/v2 router metric           (default RANDOM)\n");
	fprintf(stdout, "    --rip-domain NUM          RIPv2 router domain              (default RANDOM)\n");
	fprintf(stdout, "    --rip-tag NUM             RIPv2 router tag                 (default RANDOM)\n");
	fprintf(stdout, "    --rip-netmask ADDR        RIPv2 router subnet mask         (default RANDOM)\n");
	fprintf(stdout, "    --rip-next-hop ADDR       RIPv2 router next hop            (default RANDOM)\n");
	fprintf(stdout, "    --rip-authentication      RIPv2 authentication included    (default OFF)\n");
	fprintf(stdout, "    --rip-auth-key-id NUM     RIPv2 authentication key ID      (default 1)\n");
	fprintf(stdout, "    --rip-auth-sequence NUM   RIPv2 authentication sequence #  (default RANDOM)\n\n");
	fprintf(stdout, "DCCP Options:\n");
	fprintf(stdout, "    --dccp-data-offset NUM    DCCP data offset                 (default VARY)\n");
	fprintf(stdout, "    --dccp-cscov NUM          DCCP checksum coverage           (default 0)\n");
	fprintf(stdout, "    --dccp-ccval NUM          DCCP HC-Sender CCID              (default RANDOM)\n");
	fprintf(stdout, "    --dccp-type NUM           DCCP type                        (default %d)\n", DCCP_PKT_REQUEST);
	fprintf(stdout, "    --dccp-extended           DCCP extend for sequence #       (default OFF)\n");
	fprintf(stdout, "    --dccp-sequence-1 NUM     DCCP sequence #                  (default RANDOM)\n");
	fprintf(stdout, "    --dccp-sequence-2 NUM     DCCP extended sequence #         (default RANDOM)\n");
	fprintf(stdout, "    --dccp-sequence-3 NUM     DCCP sequence # low              (default RANDOM)\n");
	fprintf(stdout, "    --dccp-service NUM        DCCP service code                (default RANDOM)\n");
	fprintf(stdout, "    --dccp-acknowledge-1 NUM  DCCP acknowledgment # high       (default RANDOM)\n");
	fprintf(stdout, "    --dccp-acknowledge-2 NUM  DCCP acknowledgment # low        (default RANDOM)\n");
	fprintf(stdout, "    --dccp-reset-code NUM     DCCP reset code                  (default RANDOM)\n\n");
	fprintf(stdout, "RSVP Options:\n");
	fprintf(stdout, "    --rsvp-flags NUM          RSVP flags                       (default 1)\n");
	fprintf(stdout, "    --rsvp-type NUM           RSVP message type                (default 1)\n");
	fprintf(stdout, "    --rsvp-ttl NUM            RSVP time to live                (default 254)\n");
	fprintf(stdout, "    --rsvp-session-addr ADDR  RSVP SESSION destination address (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-session-proto NUM  RSVP SESSION protocol ID         (default 1)\n");
	fprintf(stdout, "    --rsvp-session-flags NUM  RSVP SESSION flags               (default 1)\n");
	fprintf(stdout, "    --rsvp-session-port NUM   RSVP SESSION destination port    (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-hop-addr ADDR      RSVP HOP neighbor address        (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-hop-iface NUM      RSVP HOP logical interface       (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-time-refresh NUM   RSVP TIME refresh interval       (default 360)\n");
	fprintf(stdout, "    --rsvp-error-addr ADDR    RSVP ERROR node address          (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-error-flags NUM    RSVP ERROR flags                 (default 2)\n");
	fprintf(stdout, "    --rsvp-error-code NUM     RSVP ERROR code                  (default 2)\n");
	fprintf(stdout, "    --rsvp-error-value NUM    RSVP ERROR value                 (default 8)\n");
	fprintf(stdout, "    --rsvp-scope NUM          RSVP SCOPE # of address(es)      (default 1)\n");
	fprintf(stdout, "    --rsvp-address ADDR,...   RSVP SCOPE address(es)           (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-style-option NUM   RSVP STYLE option vector         (default 18)\n");
	fprintf(stdout, "    --rsvp-sender-addr ADDR   RSVP SENDER TEMPLATE address     (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-sender-port NUM    RSVP SENDER TEMPLATE port        (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-tspec-traffic      RSVP TSPEC service traffic       (default OFF)\n");
	fprintf(stdout, "    --rsvp-tspec-guaranteed   RSVP TSPEC service guaranteed    (default OFF)\n");
	fprintf(stdout, "    --rsvp-tspec-r NUM        RSVP TSPEC token bucket rate     (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-tspec-b NUM        RSVP TSPEC token bucket size     (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-tspec-p NUM        RSVP TSPEC peak data rate        (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-tspec-m NUM        RSVP TSPEC minimum policed unit  (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-tspec-M NUM        RSVP TSPEC maximum packet size   (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-adspec-ishop NUM   RSVP ADSPEC IS HOP count         (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-adspec-path NUM    RSVP ADSPEC path b/w estimate    (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-adspec-m NUM       RSVP ADSPEC minimum path latency (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-adspec-mtu NUM     RSVP ADSPEC composed MTU         (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-adspec-guaranteed  RSVP ADSPEC service guaranteed   (default OFF)\n");
	fprintf(stdout, "    --rsvp-adspec-Ctot NUM    RSVP ADSPEC ETE composed value C (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-adspec-Dtot NUM    RSVP ADSPEC ETE composed value D (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-adspec-Csum NUM    RSVP ADSPEC SLR point composed C (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-adspec-Dsum NUM    RSVP ADSPEC SLR point composed D (default RANDOM)\n");
	fprintf(stdout, "    --rsvp-adspec-controlled  RSVP ADSPEC service controlled   (default OFF)\n");
	fprintf(stdout, "    --rsvp-confirm-addr ADDR  RSVP CONFIRM receiver address    (default RANDOM)\n\n");
	fprintf(stdout, "IPSEC Options:\n");
	fprintf(stdout, "    --ipsec-ah-length NUM     IPSec AH header length           (default NONE)\n");
	fprintf(stdout, "    --ipsec-ah-spi NUM        IPSec AH SPI                     (default RANDOM)\n");
	fprintf(stdout, "    --ipsec-ah-sequence NUM   IPSec AH sequence #              (default RANDOM)\n");
	fprintf(stdout, "    --ipsec-esp-spi NUM       IPSec ESP SPI                    (default RANDOM)\n");
	fprintf(stdout, "    --ipsec-esp-sequence NUM  IPSec ESP sequence #             (default RANDOM)\n\n");
	fprintf(stdout, "EIGRP Options:\n");
	fprintf(stdout, "    --eigrp-opcode NUM        EIGRP opcode                     (default %d)\n", EIGRP_OPCODE_UPDATE);
	fprintf(stdout, "    --eigrp-flags NUM         EIGRP flags                      (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-sequence NUM      EIGRP sequence #                 (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-acknowledge NUM   EIGRP acknowledgment #           (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-as NUM            EIGRP autonomous system          (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-type NUM          EIGRP type                       (default %d)\n", EIGRP_TYPE_INTERNAL);
	fprintf(stdout, "    --eigrp-length NUM        EIGRP length                     (default NONE)\n");
	fprintf(stdout, "    --eigrp-k1 NUM            EIGRP parameter K1 value         (default 1)\n");
	fprintf(stdout, "    --eigrp-k2 NUM            EIGRP parameter K2 value         (default 0)\n");
	fprintf(stdout, "    --eigrp-k3 NUM            EIGRP parameter K3 value         (default 1)\n");
	fprintf(stdout, "    --eigrp-k4 NUM            EIGRP parameter K4 value         (default 0)\n");
	fprintf(stdout, "    --eigrp-k5 NUM            EIGRP parameter K5 value         (default 0)\n");
	fprintf(stdout, "    --eigrp-hold NUM          EIGRP parameter hold time        (default 360)\n");
	fprintf(stdout, "    --eigrp-ios-ver NUM.NUM   EIGRP IOS release version        (default 12.4)\n");
	fprintf(stdout, "    --eigrp-rel-ver NUM.NUM   EIGRP PROTO release version      (default 1.2)\n");
	fprintf(stdout, "    --eigrp-next-hop ADDR     EIGRP [in|ex]ternal next-hop     (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-delay NUM         EIGRP [in|ex]ternal delay        (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-bandwidth NUM     EIGRP [in|ex]ternal bandwidth    (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-mtu NUM           EIGRP [in|ex]ternal MTU          (default 1500)\n");
	fprintf(stdout, "    --eigrp-hop-count NUM     EIGRP [in|ex]ternal hop count    (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-load NUM          EIGRP [in|ex]ternal load         (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-reliability NUM   EIGRP [in|ex]ternal reliability  (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-daddr ADDR/CIDR   EIGRP [in|ex]ternal address(es)  (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-src-router ADDR   EIGRP external source router     (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-src-as NUM        EIGRP external autonomous system (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-tag NUM           EIGRP external arbitrary tag     (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-proto-metric NUM  EIGRP external protocol metric   (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-proto-id NUM      EIGRP external protocol ID       (default 2)\n");
	fprintf(stdout, "    --eigrp-ext-flags NUM     EIGRP external flags             (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-address ADDR      EIGRP multicast sequence address (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-multicast NUM     EIGRP multicast sequence #       (default RANDOM)\n");
	fprintf(stdout, "    --eigrp-authentication    EIGRP authentication included    (default OFF)\n");
	fprintf(stdout, "    --eigrp-auth-key-id NUM   EIGRP authentication key ID      (default 1)\n\n");
	fprintf(stdout, "OSPF Options:\n");
	fprintf(stdout, "    --ospf-type NUM           OSPF type                        (default %d)\n", OSPF_TYPE_HELLO);
	fprintf(stdout, "    --ospf-length NUM         OSPF length                      (default NONE)\n");
	fprintf(stdout, "    --ospf-router-id ADDR     OSPF router ID                   (default RANDOM)\n");
	fprintf(stdout, "    --ospf-area-id ADDR       OSPF area ID                     (default 0.0.0.0)\n");
	fprintf(stdout, " -1,--ospf-option-MT          OSPF multi-topology / TOS-based  (default RANDOM)\n");
	fprintf(stdout, " -2,--ospf-option-E           OSPF external routing capability (default RANDOM)\n");
	fprintf(stdout, " -3,--ospf-option-MC          OSPF multicast capable           (default RANDOM)\n");
	fprintf(stdout, " -4,--ospf-option-NP          OSPF NSSA supported              (default RANDOM)\n");
	fprintf(stdout, " -5,--ospf-option-L           OSPF LLS data block contained    (default RANDOM)\n");
	fprintf(stdout, " -6,--ospf-option-DC          OSPF demand circuits supported   (default RANDOM)\n");
	fprintf(stdout, " -7,--ospf-option-O           OSPF Opaque-LSA                  (default RANDOM)\n");
	fprintf(stdout, " -8,--ospf-option-DN          OSPF DOWN bit                    (default RANDOM)\n");
	fprintf(stdout, "    --ospf-netmask ADDR       OSPF router subnet mask          (default RANDOM)\n");
	fprintf(stdout, "    --ospf-hello-interval NUM OSPF HELLO interval              (default RANDOM)\n");
	fprintf(stdout, "    --ospf-hello-priority NUM OSPF HELLO router priority       (default 1)\n");
	fprintf(stdout, "    --ospf-hello-dead NUM     OSPF HELLO router dead interval  (default 360)\n");
	fprintf(stdout, "    --ospf-hello-design ADDR  OSPF HELLO designated router     (default RANDOM)\n");
	fprintf(stdout, "    --ospf-hello-backup ADDR  OSPF HELLO backup designated     (default RANDOM)\n");
	fprintf(stdout, "    --ospf-neighbor NUM       OSPF HELLO # of neighbor(s)      (default NONE)\n");
	fprintf(stdout, "    --ospf-address ADDR,...   OSPF HELLO neighbor address(es)  (default RANDOM)\n");
	fprintf(stdout, "    --ospf-dd-mtu NUM         OSPF DD MTU                      (default 1500)\n");
	fprintf(stdout, "    --ospf-dd-dbdesc-MS       OSPF DD master/slave bit option  (default RANDOM)\n");
	fprintf(stdout, "    --ospf-dd-dbdesc-M        OSPF DD more bit option          (default RANDOM)\n");
	fprintf(stdout, "    --ospf-dd-dbdesc-I        OSPF DD init bit option          (default RANDOM)\n");
	fprintf(stdout, "    --ospf-dd-dbdesc-R        OSPF DD out-of-band resync       (default RANDOM)\n");
	fprintf(stdout, "    --ospf-dd-sequence NUM    OSPF DD sequence #               (default RANDOM)\n");
	fprintf(stdout, "    --ospf-dd-include-lsa     OSPF DD include LSA header       (default OFF)\n");
	fprintf(stdout, "    --ospf-lsa-age NUM        OSPF LSA age                     (default 360)\n");
	fprintf(stdout, "    --ospf-lsa-do-not-age     OSPF LSA do not age              (default OFF)\n");
	fprintf(stdout, "    --ospf-lsa-type NUM       OSPF LSA type                    (default %d)\n", LSA_TYPE_ROUTER);
	fprintf(stdout, "    --ospf-lsa-id ADDR        OSPF LSA ID address              (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-router ADDR    OSPF LSA advertising router      (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-sequence NUM   OSPF LSA sequence #              (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-metric NUM     OSPF LSA metric                  (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-flag-B         OSPF Router-LSA border router    (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-flag-E         OSPF Router-LSA external router  (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-flag-V         OSPF Router-LSA virtual router   (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-flag-W         OSPF Router-LSA wild router      (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-flag-NT        OSPF Router-LSA NSSA translation (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-link-id ADDR   OSPF Router-LSA link ID          (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-link-data ADDR OSPF Router-LSA link data        (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-link-type NUM  OSPF Router-LSA link type        (default %d)\n", LINK_TYPE_PTP);
	fprintf(stdout, "    --ospf-lsa-attached ADDR  OSPF Network-LSA attached router (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-larger         OSPF ASBR/NSSA-LSA ext. larger   (default OFF)\n");
	fprintf(stdout, "    --ospf-lsa-forward ADDR   OSPF ASBR/NSSA-LSA forward       (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lsa-external ADDR  OSPF ASBR/NSSA-LSA external      (default RANDOM)\n");
	fprintf(stdout, "    --ospf-vertex-router      OSPF Group-LSA type router       (default RANDOM)\n");
	fprintf(stdout, "    --ospf-vertex-network     OSPF Group-LSA type network      (default RANDOM)\n");
	fprintf(stdout, "    --ospf-vertex-id ADDR     OSPF Group-LSA vertex ID         (default RANDOM)\n");
	fprintf(stdout, "    --ospf-lls-extended-LR    OSPF LLS Extended option LR      (default OFF)\n");
	fprintf(stdout, "    --ospf-lls-extended-RS    OSPF LLS Extended option RS      (default OFF)\n");
	fprintf(stdout, "    --ospf-authentication     OSPF authentication included     (default OFF)\n");
	fprintf(stdout, "    --ospf-auth-key-id NUM    OSPF authentication key ID       (default 1)\n");
	fprintf(stdout, "    --ospf-auth-sequence NUM  OSPF authentication sequence #   (default RANDOM)\n\n");
	fprintf(stdout, "Some considerations while running this program:\n");
	fprintf(stdout, " 1. There is no limitation of using as many options as possible.\n");
	fprintf(stdout, " 2. Report %s bugs directly to %s <%s>.\n", program, author, email);
	fprintf(stdout, " 3. Some header fields with default values MUST be set to \'0\' for RANDOM.\n");
	fprintf(stdout, " 4. Mandatory arguments to long options are mandatory for short options too.\n");
	fprintf(stdout, " 5. Be nice when using %s, the author DENIES its use for DoS/DDoS purposes.\n", program);
#ifdef  __HAVE_T50__
	fprintf(stdout, " 6. Running %s with \'--protocol T50\' option, sends ALL protocols sequentially.\n\n", program);
#else   /* __HAVE_T50__ */
	fprintf(stdout, "\n");
#endif  /* __HAVE_T50__ */
#endif  /* __HAVE_USAGE__ */
	fprintf(stdout, "Copyright(c) 2001-2011 %s. All rights reserved worldwide.\n", author);
	fflush(stdout);
	exit(EXIT_FAILURE);
}
#endif  /* USAGE_C__ */
