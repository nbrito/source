/* 
 * $Id: usage.c,v 1.7 2009-08-16 13:13:00-03 nbrito Exp $
 *
 * Author: Nelson Brito <nbrito@sekure.org>
 *
 * Copyright© 2004-2009 Nelson Brito.
 * This file is part of F22 Raptor TCP Flood & Storm DoS Private Tool.

   This program is free software; you can redistribute it and/or modify it under
   the terms of the GNU General Public License  version 2, 1991  as published by
   the Free Software Foundation.

   This program is distributed  in the hope that it will be useful,  but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
   FOR A PARTICULAR PURPOSE.
 
   See the GNU General Public License for more details.

   A copy of the GNU General Public License can be found at:
   http://www.gnu.org/licenses/gpl.html
   or you can write to:
   Free Software Foundation, Inc.
   59 Temple Place - Suite 330
   Boston, MA  02111-1307
   USA. */
#ifndef USAGE_C__
#define USAGE_C__ 1

#include <common.h>

/* Function Name: Help routine.

   Description:   

   Targets:       N/A */
void usage(u_int8_t * program, u_int8_t * author, u_int8_t * email){
	printf("F22 Raptor TCP Flood & Storm DoS Private Tool [Version %s]\n", MAJOR_VERSION);
	printf("%s <%s>\n\n", author, email);
	printf("Usage:  %s -h [options]\n\n", program);
	printf("Common options:\n");
	printf("      --flood           Flood the target, this mode supersedes the \'--threshold\'\n");
	printf("      --threshold NUM   Threshold of events to be reached (default is 1,000)\n");
	printf("      --delay NUM       Delay in milliseconds             (default is 1)\n");
	printf("  -h, -?, --help        Display this help and exit\n\n");
	printf("IP header options:\n");
	printf("  -s, --saddr ADDRESS   Source IP address                 (default is RANDOM)\n");
	printf("  -d, --daddr ADDRESS   Destination IP address\n");
	printf("      --ttl NUM         IP time to live                   (default is 255)\n");
	printf("      --tos NUM         IP type of service                (default is IPTOS_PREC_IMMEDIATE)\n");
	printf("      --id NUM          IP ID                             (default is getpid())\n\n");
	printf("TCP header options:\n");
	printf("      --sport           TCP source port                   (default is 53)\n");
	printf("                        \'--sport 0\' is RANDOM\n");
	printf("      --dport           TCP destination port              (default is 53)\n");
	printf("                        \'--dport 0\' is RANDOM\n");
	printf("      --ack_seq NUM     TCP ACK sequence                  (default is RANDOM)\n");
	printf("  -F, --fin             TCP FIN flag                      (default is OFF)\n");
	printf("  -S, --syn             TCP SYN flag                      (default is OFF)\n");
	printf("  -R, --rst             TCP RST flag                      (default is OFF)\n");
	printf("  -P, --psh             TCP PSH flag                      (default is OFF)\n");
	printf("  -A, --ack             TCP ACK flag                      (default is OFF)\n");
	printf("  -U, --urg             TCP URG flag                      (default is OFF)\n");
	printf("  -E, --ece             TCP ECE flag                      (default is OFF)\n");
	printf("  -C, --cwr             TCP CWR flag                      (default is OFF)\n");
	printf("  -W, --window NUM      TCP Window size                   (default is RANDOM)\n");
	printf("      --urg_ptr NUM     TCP URG pointer                   (default is RANDOM)\n\n");
	printf("Copyright(c) 2004-2009 %s. All rights reserved worldwide.\n", author);
	exit(EXIT_FAILURE);
}
#endif  /* USAGE_C__ */
