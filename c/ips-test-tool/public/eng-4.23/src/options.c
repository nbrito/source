/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the ENG Private Tool by Nelson Brito.

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
   $Id: options.c,v 1.9 2008-09-14 17:57:14-03 nbrito Exp $ */
#include "options.h"

/* Options processing routine. */
const struct options process_options(int argc, char ** argv){
	int32_t lineopt;
	struct offset offset ={	NULL, 0 };
	/* Command-line options structure. */
	struct options options = {
		/* Informational options.                          */
		0,                     /* do not show copyright    */
		
		/* NIPS options.                                   */
		DEFAULT_SHELLCODE_ID,    /* default shellcode ID       */
		DEFAULT_OFFSET_ID,     /* default offset ID        */
		DEFAULT_CMD_PORT,      /* default port is 22 (SSH) */

		/* IP header options.                              */
		IPTOS_PREC_IMMEDIATE, /* default type of service   */
		0xff,                 /* defautl time to live      */
		getpid(),             /* default identification    */
		INADDR_ANY,           /* source address            */
		INADDR_ANY,           /* destination address       */

		/* General header options (UDP & TCP).             */		
		IPPORT_DEFAULT,       /* source port               */
		IPPORT_SSRP,          /* destination port          */
	};

	/* Command-line options which do not have short options.  */
	enum {
		COPYRIGHT,
		TOS,
		TTL,
		ID,
		SOURCE,
		SHELLCODE,
		OFFSET,
		PORT,
	};

	static const struct option long_options[] = {
		{ "daddr",          required_argument, NULL, 'd'         },
		{ "saddr",          required_argument, NULL, 's'         },
		{ "source",         required_argument, NULL, SOURCE      },
		{ "tos",            required_argument, NULL, TOS         },
		{ "ttl",            required_argument, NULL, TTL         },
		{ "id",             required_argument, NULL, ID          },
		{ "list-shellcode", no_argument,       NULL, 'S'         },
		{ "list-offset",    no_argument,       NULL, 'O'         },
		{ "shellcode",      required_argument, NULL, SHELLCODE   },
		{ "offset",         required_argument, NULL, OFFSET      },
		{ "port",           required_argument, NULL, PORT        },
		{ "help",           no_argument,       NULL, 'h'         },
		{ "copyright",      no_argument,       NULL, COPYRIGHT   },
		{ 0,                0,                 NULL, 0           }
	};

	while(1){
		int32_t option_index = 0;

		if((lineopt = getopt_long(argc, argv, "s:d:SOh", long_options, &option_index)) == -1)
			break;

		switch(lineopt){
			case TTL:
				options.ttl = atoi(optarg);
				break;
			case TOS:
				options.tos = atoi(optarg);
				break;
			case ID:
				options.id = atoi(optarg);
				break;
			case 's':
				options.saddr = resolv(optarg);
				break;
			case 'd':
				options.daddr = resolv(optarg);
				break;
			case SOURCE:
				options.source = atoi(optarg);
				break;
			case SHELLCODE:
				options.shellcode = atoi(optarg);
				break;
			case 'S':
				process_shellcode(DISPLAY_ALL_SHELLCODES, DISPLAY_ALL_SHELLCODES);
				break;
			case OFFSET:
				options.offset = atoi(optarg);
				break;
			case 'O':
				process_offset(DISPLAY_ALL_OFFSETS, offset);
				break;
			case PORT:
				options.port = atoi(optarg);
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

	/* Printing some infomation. */
	if(options.copyright){
		nb(banner, 31337);
		nb(copyright,  31337);
		exit(EXIT_SUCCESS);
	}

	/* Warning missed target. */
	if(options.daddr == INADDR_ANY){
		printf("you must specify the target to run the %s\n", program);
		printf("type \"%s --help\" for further information\n", program);
		exit(EXIT_FAILURE);
	}

	return(options);
}
#endif  /* OPTIONS_C__ */
