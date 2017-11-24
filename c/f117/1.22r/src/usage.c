/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the F117 Private Tool by Nelson Brito.

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
/* Nelson Brito <nbrito@sekure.org>
   $Id: usage.c,v 1.1 2008-09-12 15:36:14-03 nbrito Exp $ */
#include "common.h"

/* Usage help message. 
   Returns the usage to process_options(). */
void usage(int8_t * program, int8_t * author, int8_t * email){
	printf("F117 v%s.%s - TCP Flood & Storm Next Generation DoS Tool\n", __MAJOR_VERSION, __MINOR_VERSION);
	printf("%s <%s>\n\n", author, email);
	printf("Usage:  %s -h [options]\n\n", program);
	printf("Flood options:\n");
	printf("      --threshold NUM   threshold of events to be reached (default is 1,000)\n");
	printf("      --flood           flood the target, this mode supersedes the \'--threshold\'\n");
	printf("      --delay NUM       delay in milliseconds (default is 1)\n\n");
	printf("TCP header options:\n");
	printf("  -F, --fin             TCP FIN flag (default is OFF)\n");
	printf("  -S, --syn             TCP SYN flag (default is OFF)\n");
	printf("  -R, --rst             TCP RST flag (default is OFF)\n");
	printf("  -P, --psh             TCP PSH flag (default is OFF)\n");
	printf("  -A, --ack             TCP ACK flag (default is OFF)\n");
	printf("  -U, --urg             TCP URG flag (default is OFF)\n");
	printf("      --sport           TCP source port (default is 53)\n");
	printf("                        \'--sport 0\' is RANDOM TCP source port\n");
	printf("      --dport           TCP destination port (default is 53)\n");
	printf("                        \'--dport 0\' is RANDOM TCP destination port\n\n");
	printf("IP header options:\n");
	printf("  -s, --saddr ADDRESS   source IP address (default is RANDOM)\n");
	printf("  -d, --daddr ADDRESS   destination IP address\n");
	printf("      --ttl NUM         IP time to live (default is 255)\n");
	printf("      --tos NUM         IP type of service (default is IPTOS_PREC_IMMEDIATE)\n");
	printf("      --id NUM          IP ID (default is getpid())\n\n");
	printf("  -h, --help            display this help and exit\n\n");
	printf("F117 v%s.%s Copyright© 2004-2008 %s <%s>.\n", __MAJOR_VERSION, __MINOR_VERSION, author, email);
	printf("All rights reserved worldwide.\n");
	exit(EXIT_FAILURE);
}
#endif  /* USAGE_C__ */
