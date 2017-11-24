/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the NNG Private Tool by Nelson Brito.

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
#ifndef OPTIONS_C__
#define OPTIONS_C__ 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: options.c,v 1.1 2008-09-13 13:42:46-03 nbrito Exp $ */
#include "options.h"

/* Options processing routine. */
const struct options process_options(int argc, char ** argv){
	int32_t lineopt;

	/* Command-line options structure. */
	struct options options = {
		/* Common options.                                */
		1000,                /* default threshold         */
		0,                   /* do not flood              */
		1,                   /* default delay is 1 msec   */
		0,                   /* do not show copyright     */
		/* NIPS options.                                  */
		0,                   /* default payload ID        */
		PROCESS_ALL_PAYLOADS,/* default payload option    */
		/* IP header options.                             */
		IPTOS_PREC_IMMEDIATE,/* default type of service   */
		0xff,                /* defautl time to live      */
		getpid(),            /* default identification    */
		INADDR_ANY,          /* source address            */
		INADDR_ANY,          /* destination address       */
		/* General header options (UDP & TCP).            */
		IPPORT_ANY,          /* general source port       */
		IPPORT_ANY,          /* general destination port  */
	};

	/* Command-line options which do not have short options. */
	enum {
		COPYRIGHT,
		THRESHOLD,
		FLOOD,
		DELAY,
		TOS,
		TTL,
		ID,
		LIST,
		PAYLOAD,
	};

	static const struct option long_options[] = {
		{ "threshold", required_argument, NULL, THRESHOLD },
		{ "saddr",     required_argument, NULL, 's'       },
		{ "daddr",     required_argument, NULL, 'd'       },
		{ "tos",       required_argument, NULL, TOS       },
		{ "ttl",       required_argument, NULL, TTL       },
		{ "id",        required_argument, NULL, ID        },
		{ "delay",     required_argument, NULL, DELAY     },
		{ "list",      no_argument,       NULL, LIST      },
		{ "payload",   required_argument, NULL, PAYLOAD   },
		{ "help",      no_argument,       NULL, 'h'       },
		{ "copyright", no_argument,       NULL, COPYRIGHT },
		{ "flood",     no_argument,       NULL, FLOOD     },
		{ 0,           0,                 NULL, 0         }
	};

	while(1){
		int32_t option_index = 0;

		if((lineopt = getopt_long(argc, argv, "s:d:h", long_options, &option_index)) == -1)
			break;

		switch(lineopt){
			case TTL:
				options.ttl = atoi(optarg);
				if(options.ttl > 255){
					printf("TTL must not be greater than 255\n");
					exit(EXIT_FAILURE);
				}
				break;
			case TOS:
				options.tos = atoi(optarg);
				break;
			case ID:
				options.id = atoi(optarg);
				break;
			case THRESHOLD:
				options.threshold = atoi(optarg);
				if(options.threshold < 1){
					printf("threshold must be greater than 0\n");
					exit(EXIT_FAILURE);
				}
				break;
			case DELAY:
				options.delay = atoi(optarg);
				break;
			case FLOOD:
				options.flood++;
				break;
			case 's':
				options.saddr = resolv(optarg);
				break;
			case 'd':
				options.daddr = resolv(optarg);
				break;
			case PAYLOAD:
				options.payload = atoi(optarg);
				options.procopt = PROCESS_USER_PAYLOAD;
				break;
			case LIST:
				options.procopt = DISPLAY_ALL_PAYLOADS;
				process_payload(0, 0, options.procopt);
				break;
			case COPYRIGHT:
				options.copyright++;
				break;
			case 'h':
				usage(program, author, email);
				break;
			default:
				printf("type \"%s --help\" for further information\n", program);
				exit(EXIT_FAILURE);
				break;
		}
	}

	argc -= optind;
	argv += optind;

	/* Printing little banner. */
	printf("%s v%s.%s [built on %s %s]\n", program, __MAJOR_VERSION, __MINOR_VERSION, __DATE__, __TIME__);

	if(options.copyright){
		nb(banner,  31337);
		nb(copyright,  31337);
		exit(EXIT_SUCCESS);
	}

	/* Warning missed target. */
	if(options.daddr == INADDR_ANY){
		printf("you must specify the target to run the %s\n", program);
		printf("type \"%s --help\" for further information\n", program);
		exit(EXIT_FAILURE);
	}

#ifndef __CYGWIN__
        /* Warning missed privileges. */
	if(getuid()){
		printf("you must have privileges to run the %s\n", program);
		exit(EXIT_FAILURE);
	}
#endif  /* __CYGWIN__ */


	return(options);
}
#endif  /* OPTIONS_C__ */
