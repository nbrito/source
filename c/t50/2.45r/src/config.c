/* 
 * $Id: config.c,v 3.9 2010-11-27 14:48:12-02 nbrito Exp $
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
#ifndef CONFIG_C__
#define CONFIG_C__ 1

#include <common.h>


/* Local Global Variables. */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 3.9 $";
#endif  /* __HAVE_DEBUG__ */


#ifndef __USE_XOPEN_EXTENDED
/* Parse comma separate list into words.
   Copyright (C) 1996, 1997, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/* This function doesn't exist on most systems (this replacement is
   lifted from the libc sources. */
#if !defined HAVE___STRCHRNUL && !defined _LIBC
static char * __strchrnul (const char *s, int c);
static char * __strchrnul (const char *s, int c)
{
  char *result = strchr (s, c);
  if (result == NULL)
    result = strchr (s, '\0');
  return result;
}
# endif

/* Parse comma separated suboption from *OPTIONP and match against
   strings in TOKENS.  If found return index and set *VALUEP to
   optional value introduced by an equal sign.  If the suboption is
   not part of TOKENS return in *VALUEP beginning of unknown
   suboption.  On exit *OPTIONP is set to the beginning of the next
   token or at the terminating NUL character.  */
int getsubopt (char ** optionp, char * const * tokens, char ** valuep){
  char * endp, * vstart;
  int cnt;

  if (**optionp == '\0')
    return -1;

  /* Find end of next token.  */
  endp = __strchrnul (*optionp, ',');

  /* Find start of value.  */
  vstart = memchr (*optionp, '=', endp - *optionp);
  if (vstart == NULL)
    vstart = endp;

  /* Try to match the characters between *OPTIONP and VSTART against
     one of the TOKENS.  */
  for (cnt = 0; tokens[cnt] != NULL; ++cnt)
    if (memcmp (*optionp, tokens[cnt], vstart - *optionp) == 0
	&& tokens[cnt][vstart - *optionp] == '\0')
      {
	/* We found the current option in TOKENS.  */
	*valuep = vstart != endp ? vstart + 1 : NULL;

	if (*endp != '\0')
	  *endp++ = '\0';
	*optionp = endp;

	return cnt;
      }

  /* The current suboption does not match any option.  */
  *valuep = *optionp;

  if (*endp != '\0')
    *endp++ = '\0';
  *optionp = endp;

  return -1;
}
#endif  /* __USE_XOPEN_EXTENDED */


/* Function Name: Command line interface options configuration.

   Description:   This function configures the command line interface options.

   Targets:       N/A */
struct config_options config(int32_t argc, int8_t ** argv){
	/* Command line interface and counter. */
	static int32_t command_line_interface_options, x = 0;
	/* The following variables will be used by 'getsubopt()'. */
	static char * optionp, * valuep;

	/* Command line interface options structures. */
	static struct config_options o = {
		/* XXX COMMON OPTIONS XXX                                                     */
		1000,                               /* default threshold                      */
		0,                                  /* do not flood                           */
		0,                                  /* do not use bogus checksum              */
#ifdef  __HAVE_TURBO__
		0,                                  /* do not duplicate the attack            */
#endif  /* __HAVE_TURBO__ */
		0,                                  /* do not show copyright                  */
		/* XXX IP HEADER OPTIONS XXX                                                  */
		{	IPTOS_PREC_IMMEDIATE,       /* default type of service                */
			0,                          /* default identification                 */
			0,                          /* defautl fragmentation offset           */
			255,                        /* defautl time to live                   */
			IPPROTO_TCP,                /* default packet protocol                */
			OPTION_TCP,                 /* default protocol name                  */
			INADDR_ANY,                 /* source address                         */
			INADDR_ANY         },       /* destination address                    */
		/* XXX UDP & TCP HEADER OPTIONS XXX                                           */
		IPPORT_ANY,                         /* no default source port                 */
		IPPORT_ANY,                         /* no default destination port            */
		/* XXX TCP HEADER OPTIONS XXX                                                 */
		{	0,                          /* sequence number                        */
			0,                          /* acklowdgement sequence                 */
			0,                          /* end of data flag                       */
			0,                          /* synchronize ISN flag                   */
			0,                          /* reset connection flag                  */
			0,                          /* push flag                              */
			0,                          /* acknowledgment # valid flag            */
			0,                          /* urgent pointer valid flag              */
			0,                          /* ecn-echo                               */
			0,                          /* congestion windows reduced             */
			0,                          /* TCP window size                        */
			0                 },        /* urgent pointer data                    */
		/* XXX ICMP HEADER OPTIONS XXX                                                */
		{	ICMP_ECHO,                  /* default control message type           */
			0,                          /* default control message code           */
			0,                          /* default control message identification */
			0,                          /* default control message sequence       */
			INADDR_ANY         }      , /* destination address                    */
		{	IGMP_HOST_MEMBERSHIP_QUERY, /* default group type                     */
			0,                          /* default group code                     */
			INADDR_ANY },               /* default group address                  */
	};

	/* Command-line options which do not have short options. */
	enum {
		OPTION_THRESHOLD,
		OPTION_FLOOD,
#ifdef  __HAVE_TURBO__
		OPTION_TURBO,
#endif  /* __HAVE_TURBO__ */
		OPTION_COPYRIGHT,
		OPTION_IP_TOS,
		OPTION_IP_ID,
		OPTION_IP_FRAG_OFF,
		OPTION_IP_TTL,
		OPTION_IP_PROTOCOL,
		OPTION_SOURCE,
		OPTION_DESTINATION,
		OPTION_TCP_ACK_SEQ,
		OPTION_TCP_SYN_SEQ,
		OPTION_TCP_URG_PTR,
		OPTION_ICMP_TYPE,
		OPTION_ICMP_CODE,
		OPTION_ICMP_ID,
		OPTION_ICMP_SEQ,
		OPTION_ICMP_GATEWAY,
		OPTION_IGMP_TYPE,
		OPTION_IGMP_CODE,
		OPTION_IGMP_GROUP,

	};

	static const struct option long_opt[] = {
		/* XXX COMMON OPTIONS XXX */
		{ "threshold",     required_argument, NULL, OPTION_THRESHOLD    },
		{ "flood",         no_argument,       NULL, OPTION_FLOOD        },
		{ "bogus-csum",    no_argument,       NULL, 'B'                 },
#ifdef  __HAVE_TURBO__
		{ "turbo",         no_argument,       NULL, OPTION_TURBO        },
#endif  /* __HAVE_TURBO__ */
		{ "copyright",     no_argument,       NULL, OPTION_COPYRIGHT    },
		{ "help",          no_argument,       NULL, 'h'                 },
		/* XXX IP HEADER OPTIONS XXX */
		{ "saddr",         required_argument, NULL, 's'                 },
		{ "tos",           required_argument, NULL, OPTION_IP_TOS       },
		{ "id",            required_argument, NULL, OPTION_IP_ID        },
		{ "frag-off",      required_argument, NULL, OPTION_IP_FRAG_OFF  },
		{ "ttl",           required_argument, NULL, OPTION_IP_TTL       },
		{ "protocol",      required_argument, NULL, OPTION_IP_PROTOCOL  },
		/* XXX UDP & TCP HEADER OPTIONS XXX */
		{ "sport",         required_argument, NULL, OPTION_SOURCE       },
		{ "dport",         required_argument, NULL, OPTION_DESTINATION  },
		/* XXX TCP HEADER OPTIONS XXX */
		{ "ack-sequence",  required_argument, NULL, OPTION_TCP_ACK_SEQ  },
		{ "sequence",      required_argument, NULL, OPTION_TCP_SYN_SEQ  },
		{ "fin",           no_argument,       NULL, 'F'                 },
		{ "syn",           no_argument,       NULL, 'S'                 },
		{ "rst",           no_argument,       NULL, 'R'                 },
		{ "psh",           no_argument,       NULL, 'P'                 },
		{ "ack",           no_argument,       NULL, 'A'                 },
		{ "urg",           no_argument,       NULL, 'U'                 },
		{ "ece",           no_argument,       NULL, 'E'                 },
		{ "cwr",           no_argument,       NULL, 'C'                 },
		{ "window",        required_argument, NULL, 'W'                 },
		{ "urg-pointer",   required_argument, NULL, OPTION_TCP_URG_PTR  },
		/* XXX ICMP HEADER OPTIONS XXX */
		{ "icmp-type",     required_argument, NULL, OPTION_ICMP_TYPE    },
		{ "icmp-code",     required_argument, NULL, OPTION_ICMP_CODE    },
		{ "icmp-id",       required_argument, NULL, OPTION_ICMP_ID      },
		{ "icmp-sequence", required_argument, NULL, OPTION_ICMP_SEQ     },
		{ "icmp-gateway",  required_argument, NULL, OPTION_ICMP_GATEWAY },
		/* XXX IGMP HEADER OPTIONS XXX */
		{ "igmp-type",     required_argument, NULL, OPTION_IGMP_TYPE    },
		{ "igmp-code",     required_argument, NULL, OPTION_IGMP_CODE    },
		{ "igmp-group",    required_argument, NULL, OPTION_IGMP_GROUP   },
		{ 0,               0,                 NULL, 0                   }
	};

	/* Checking command line interface options. */
	while(1){
		static int32_t opt_ind = 0;

		if((command_line_interface_options = getopt_long(argc, argv, "s:FSRPAUECW:Bh?", long_opt, &opt_ind)) == -1)
			break;

		switch(command_line_interface_options){
			/* XXX COMMON OPTIONS XXX */
			case OPTION_THRESHOLD:
				o.threshold = atoi(optarg);
				break;
			case OPTION_FLOOD:
				o.flood = 0;
				break;
			case 'B':
				o.bogus_csum = 1;
				break;
#ifdef  __HAVE_TURBO__
			case OPTION_TURBO:
				o.turbo++;
				break;
#endif  /* __HAVE_TURBO__ */
			case OPTION_COPYRIGHT:
				nb(copyright, 31337);
				exit(EXIT_SUCCESS);
				break;
			/* XXX IP HEADER OPTIONS XXX */
			case OPTION_IP_TOS:
				o.ip.tos = atoi(optarg);
				break;
			case OPTION_IP_ID:
				o.ip.id = atoi(optarg);
				break;
			case OPTION_IP_FRAG_OFF:
				o.ip.frag_off = atoi(optarg);
				break;
			case OPTION_IP_TTL:
				o.ip.ttl = atoi(optarg);
				break;
			case 's':
				o.ip.saddr = resolv(optarg);
				break;
			case OPTION_IP_PROTOCOL:
				optionp = optarg;
				while (*optionp != '\0'){
					switch(x = getsubopt(&optionp, protocols, &valuep)){
						case OPTION_ICMP:
							o.ip.protocol  = IPPROTO_ICMP;
							o.ip.protoname = x;
							break;
						case OPTION_IGMP:
							o.ip.protocol  = IPPROTO_IGMP;
							o.ip.protoname = x;
							break;
						case OPTION_TCP:
							o.ip.protocol  = IPPROTO_TCP;
							o.ip.protoname = x;
							break;
						case OPTION_UDP:
							o.ip.protocol  = IPPROTO_UDP;
							o.ip.protoname = x;
							break;
#ifdef  __HAVE_T50__
						case OPTION_T50:
							o.ip.protocol  = IPPROTO_T50;
							o.ip.protoname = x;
							break;
#endif  /* __HAVE_T50__ */
						default:
#ifdef  __HAVE_DEBUG__
							ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
							fprintf(stderr, "%s(): Protocol %s is not implememted\n", __FUNCTION__, optarg);
							fflush(stderr);
							exit(EXIT_FAILURE);
							break;
					}
				}
				break;
			/* XXX UDP & TCP HEADER OPTIONS XXX */
			case OPTION_SOURCE:
				o.source = atoi(optarg);
				break;
			case OPTION_DESTINATION:
				o.dest = atoi(optarg);
				break;
			/* XXX TCP HEADER OPTIONS XXX */
			case OPTION_TCP_SYN_SEQ:
				o.tcp.seq = atoi(optarg);
				break;
			case OPTION_TCP_ACK_SEQ:
				o.tcp.ack_seq = atoi(optarg);
				break;
			case 'F':
				o.tcp.fin = 1;
				break;
			case 'S':
				o.tcp.syn = 1;
				break;
			case 'R':
				o.tcp.rst = 1;
				break;
			case 'P':
				o.tcp.psh = 1;
				break;
			case 'A':
				o.tcp.ack = 1;
				break;
			case 'U':
				o.tcp.urg = 1;
				break;
			case 'E':
				o.tcp.ece = 1;
				break;
			case 'C':
				o.tcp.cwr = 1;
				break;
			case 'W':
				o.tcp.window = atoi(optarg);
				break;
			case OPTION_TCP_URG_PTR:
				o.tcp.urg_ptr = atoi(optarg);
				break;
			/* XXX ICMP HEADER OPTIONS XXX */
			case OPTION_ICMP_TYPE:
				o.icmp.type = atoi(optarg);
				break;
			case OPTION_ICMP_CODE:
				o.icmp.code = atoi(optarg);
				break;
			case OPTION_ICMP_ID:
				o.icmp.id = atoi(optarg);
				break;
			case OPTION_ICMP_SEQ:
				o.icmp.sequence = atoi(optarg);
				break;
			case OPTION_ICMP_GATEWAY:
				o.icmp.gateway = resolv(optarg);
				break;
			/* XXX IGMP HEADER OPTIONS XXX */
			case OPTION_IGMP_TYPE:
				o.igmp.type = atoi(optarg);
				break;
			case OPTION_IGMP_CODE:
				o.igmp.code = atoi(optarg);
				break;
			case OPTION_IGMP_GROUP:
				o.igmp.group = resolv(optarg);
				break;
			/* XXX HELP / USAGE MESSAGE */
			case 'h':
			case '?':
			/* The 'default' is just to make sense. Never lands here. */
			default:
				usage(program, author, email);
				break;
		}
	}

	/* Checking the command line interface options. */
	if (optind >= argc) {
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr, "Type \"%s --help\" for further information.\n", program);
		fflush(stderr);
		exit(EXIT_FAILURE);
	}

	/* Resolving destination address. */
	o.ip.daddr = resolv(argv[optind]);

	/* Returning configurated options. */
	return(o);
}
#endif  /* CONFIG_C__ */
