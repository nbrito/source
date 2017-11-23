/* 
 * $Id: usage.c,v 3.12 2010-11-27 14:48:12-02 nbrito Exp $
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
#ifndef USAGE_C__
#define USAGE_C__ 1

#include <common.h>

/* Function Name: Help and usage message.

   Description:   This function shows help and usage message.

   Targets:       N/A */
void usage(int8_t * program, int8_t * author, int8_t * email){
	fprintf(stdout, "T50 Sukhoi PAK FA");
#ifdef  __HAVE_T50__
	fprintf(stdout, " Mixed ");
#else   /* __HAVE_T50__ */
	fprintf(stdout, " ");
#endif  /* __HAVE_T50__ */
	fprintf(stdout, "Packet Injector Tool [Version %s", MAJOR_VERSION);

#ifdef  __HAVE_LIMITATION__
	fprintf(stdout, " & RFC1918 Compliance]\n");
#else   /* __HAVE_LIMITATION__ */
	fprintf(stdout, "]\n");
#endif  /* __HAVE_LIMITATION__ */
	fprintf(stdout, "%s <%s>\n\n", author, email);
	fprintf(stdout, "Usage:  %s host [options]\n\n", program);
#ifdef __HAVE_USAGE__
	fprintf(stdout, "Common Options:\n");
	fprintf(stdout, "     --flood              Flood the host, this mode supersedes the \'threshold\'\n");
	fprintf(stdout, "     --threshold NUM      Threshold of packets to send     (default is 1,000)\n");
	fprintf(stdout, "  -B,--bogus-csum         Bogus checksum                   (default is OFF)\n");
#ifdef  __HAVE_TURBO__
	fprintf(stdout, "     --turbo              Extend the performance           (default is OFF)\n");
#endif  /* __HAVE_TURBO__ */
	fprintf(stdout, "     --copyright          Display the copyright\n");
	fprintf(stdout, "  -h,-?,--help            Display this help and exit\n\n");
	fprintf(stdout, "IP Options:\n");
	fprintf(stdout, "  -s,--saddr ADDR         Source IP address                (default is RANDOM)\n");
	fprintf(stdout, "     --tos NUM            Type of service                  (default is 0x%x)\n", IPTOS_PREC_IMMEDIATE);
	fprintf(stdout, "     --id NUM             Identification                   (default is RANDOM)\n");
	fprintf(stdout, "     --frag-off NUM       Fragmentation offset             (default is 0)\n");
	fprintf(stdout, "     --ttl NUM            Time to live                     (default is 255)\n");
#ifdef  __HAVE_T50__
	fprintf(stdout, "     --protocol PROTO     Protocol (ICMP/IGMP/TCP/UDP/T50) (default is TCP)\n\n");
#else   /* __HAVE_T50__ */
	fprintf(stdout, "     --protocol PROTO     Protocol (ICMP/IGMP/TCP/UDP)     (default is TCP)\n\n");
#endif  /* __HAVE_DEBUG__ */
	fprintf(stdout, "TCP & UDP Options:\n");
	fprintf(stdout, "     --sport NUM          Source port                      (default is RANDOM)\n");
	fprintf(stdout, "     --dport NUM          Destination port                 (default is RANDOM)\n\n");
	fprintf(stdout, "TCP Options:\n");
	fprintf(stdout, "     --sequence NUM       SYN sequence                     (default is RANDOM)\n");
	fprintf(stdout, "     --ack-sequence NUM   ACK sequence                     (default is RANDOM)\n");
	fprintf(stdout, "  -F,--fin                FIN flag                         (default is OFF)\n");
	fprintf(stdout, "  -S,--syn                SYN flag                         (default is OFF)\n");
	fprintf(stdout, "  -R,--rst                RST flag                         (default is OFF)\n");
	fprintf(stdout, "  -P,--psh                PSH flag                         (default is OFF)\n");
	fprintf(stdout, "  -A,--ack                ACK flag                         (default is OFF)\n");
	fprintf(stdout, "  -U,--urg                URG flag                         (default is OFF)\n");
	fprintf(stdout, "  -E,--ece                ECE flag                         (default is OFF)\n");
	fprintf(stdout, "  -C,--cwr                CWR flag                         (default is OFF)\n");
	fprintf(stdout, "  -W,--window NUM         Window size                      (default is RANDOM)\n");
	fprintf(stdout, "     --urg-pointer NUM    URG pointer                      (default is RANDOM)\n\n");
	fprintf(stdout, "ICMP Options:\n");
	fprintf(stdout, "     --icmp-type NUM      Control type                     (default is 8)\n");
	fprintf(stdout, "     --icmp-code NUM      Control code                     (default is 0)\n");
	fprintf(stdout, "     --icmp-gateway ADDR  Redirect gateway                 (default is RANDOM)\n");
	fprintf(stdout, "     --icmp-id NUM        Control identification           (default is RANDOM)\n");
	fprintf(stdout, "     --icmp-sequence NUM  Control sequence                 (default is RANDOM)\n\n");
	fprintf(stdout, "IGMP Options:\n");
	fprintf(stdout, "     --igmp-type NUM      Group type                       (default is 0x%x)\n", IGMP_HOST_MEMBERSHIP_QUERY);
	fprintf(stdout, "     --igmp-code NUM      Group code                       (default is 0)\n");
	fprintf(stdout, "     --igmp-group ADDR    Group address                    (default is RANDOM)\n\n");
	fprintf(stdout, "Mandatory arguments to long options are mandatory for short options too.\n\n");
#endif /* __HAVE_USAGE__ */
	fprintf(stdout, "Copyright(c) 2001-2010 %s. All rights reserved worldwide.\n", author);
	fflush(stdout);
	exit(EXIT_FAILURE);
}
#endif  /* USAGE_C__ */
