/* Copyright© 2004-2008 Nelson Brito
 * This file is part of the B52 Private Tool by Nelson Brito.

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
   $Id: options.c,v 1.2 2008-08-23 11:35:58-03 nbrito Exp $ */
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
		/* IP header options.                             */
		IPTOS_PREC_IMMEDIATE,/* default type of service   */
		0xff,                /* defautl time to live      */
		getpid(),            /* default identification    */
		INADDR_ANY,          /* source address            */
		INADDR_ANY,          /* destination address       */
		/* General header options (UDP & TCP).            */
		IPPORT_DNS,          /* general source port       */
		IPPORT_ANY,          /* general destination port  */
		8,                   /* general packet length     */
	};

	/* Command-line options which do not have short options. */
	enum {
		COPYRIGHT,
		THRESHOLD,
		FLOOD,
		DELAY,
		TOS,
		SOURCE,
		DESTINATION,
		LENGTH,
		TTL,
		ID,
	};

	static const struct option long_options[] = {
		{ "threshold", required_argument, NULL, THRESHOLD   },
		{ "saddr",     required_argument, NULL, 's'         },
		{ "daddr",     required_argument, NULL, 'd'         },
		{ "tos",       required_argument, NULL, TOS         },
		{ "ttl",       required_argument, NULL, TTL         },
		{ "sport",     required_argument, NULL, SOURCE      },
		{ "dport",     required_argument, NULL, DESTINATION },
		{ "id",        required_argument, NULL, ID          },
		{ "delay",     required_argument, NULL, DELAY       },
		{ "help",      no_argument,       NULL, 'h'         },
		{ "copyright", no_argument,       NULL, COPYRIGHT   },
		{ "flood",     no_argument,       NULL, FLOOD       },
		{ "length",    required_argument, NULL, LENGTH      },
		{ 0,           0,                 NULL, 0           }
	};

	while(1){
		int32_t option_index = 0;

		if((lineopt = getopt_long(argc, argv, "s:d:h", long_options, &option_index)) == -1)
			break;

		switch(lineopt){
			case TTL:
				options.ttl = atoi(optarg);
				if(options.ttl > 255){
#ifdef  __HAVE_DEBUG__

					printf("function %s in file %s (line %d)\n",
						__FUNCTION__,
						__FILE__,
						(__LINE__ - 6));

#endif  /* __HAVE_DEBUG__ */
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
#ifdef  __HAVE_DEBUG__

					printf("function %s in file %s (line %d)\n",
						__FUNCTION__,
						__FILE__,
						(__LINE__ - 6));

#endif  /* __HAVE_DEBUG__ */
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
			case SOURCE:
				options.source = atoi(optarg);
				if(options.source > 65535){
#ifdef  __HAVE_DEBUG__
					printf("function %s in file %s (line %d)\n",
							__FUNCTION__,
							__FILE__,
							(__LINE__ - 6));
#endif  /* __HAVE_DEBUG__ */
					printf("source port must be greater than 0 and lesser than 65535\n");
					exit(EXIT_FAILURE);
				}
				break;
			case DESTINATION:
				options.dest = atoi(optarg);
				if(options.dest > 65535){
#ifdef  __HAVE_DEBUG__
					printf("function %s in file %s (line %d)\n",
							__FUNCTION__,
							__FILE__,
							(__LINE__ - 6));
#endif  /* __HAVE_DEBUG__ */
					printf("destination port must be greater than 0 and lesser than 65535\n");
					exit(EXIT_FAILURE);
				}
				break;
			case LENGTH:
				options.length = atoi(optarg);
				if((options.length > 1472) || (options.length < 0)){
#ifdef  __HAVE_DEBUG__
					printf("function %s in file %s (line %d)\n",
							__FUNCTION__,
							__FILE__,
							(__LINE__ - 6));
#endif  /* __HAVE_DEBUG__ */
					printf("packet length must be greater than 0 and lesser than 1472\n");
					exit(EXIT_FAILURE);
				}
				break;
			case COPYRIGHT:
				options.copyright++;
				break;
			case 'h':
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

	/* Printing little banner. */
	printf("%s v%s [built on %s %s]\n", program, __VERSION, __DATE__, __TIME__);

	if(options.copyright){
		nb(copyright,  31337);
		exit(EXIT_SUCCESS);
	}

	/* Warning missed target. */
	if(options.daddr == INADDR_ANY){
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

	return(options);
}
#endif  /* OPTIONS_C__ */
