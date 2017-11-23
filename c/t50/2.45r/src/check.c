/* 
 * $Id: check.c,v 3.5 2010-11-27 14:48:12-02 nbrito Exp $
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
#ifndef CHECK_C__
#define CHECK_C__ 1

#include <common.h>


/* Local Global Variables. */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 3.5 $";
#endif  /* __HAVE_DEBUG__ */


/* Function Name: Command line interface options validation.

   Description:   This function validades the command line interface options.

   Targets:       N/A */
u_int32_t check(const struct config_options o, const int8_t * program){
	/* Warning missed privileges. */
	if(getuid()){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr, "%s(): You must have privileges to run the %s\n", __FUNCTION__, program);
		fflush(stderr);
		return(0);
	}

	/* Warning missed target. */
	if(o.ip.daddr == INADDR_ANY){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr, "Type \"%s --help\" for further information.\n", program);
		fflush(stderr);
		return(0);
	}

#ifdef  __HAVE_LIMITATION__
	/* Testing IANA IP address allocation for private internets (RFC 1918). */
	switch(ntohl(o.ip.daddr) & 0xff000000){
		/* Allowing 10/8 (RFC 1918). */
		case 0x0a000000:
			break;
		/* Allowing 172.16/12 (RFC 1918). */
		case 0xac000000:
			if(((ntohl(o.ip.daddr) & 0xffff0000) < 0xac100000) || ((ntohl(o.ip.daddr) & 0xffff0000) > 0xac1f0000)){
#ifdef  __HAVE_DEBUG__
				ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
				fprintf(stderr, "%s(): Limited version is RFC 1918 compliance\n", __FUNCTION__);
				fflush(stderr);
				return(0);
			}
			break;
		/* Allowing 192.168/16 (RFC 1918). */
		case 0xc0000000:
			if((ntohl(o.ip.daddr) & 0xffff0000) != 0xc0a80000){
#ifdef  __HAVE_DEBUG__
				ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
				fprintf(stderr, "%s(): Limited version is RFC 1918 compliance\n", __FUNCTION__);
				fflush(stderr);
				return(0);
			}
			break;
		/* Blocking all other IP addresses. */
		default:
#ifdef  __HAVE_DEBUG__
			ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
			fprintf(stderr, "%s(): Limited version is RFC 1918 compliance\n", __FUNCTION__);
			fflush(stderr);
			return(0);
			break;
	}
#endif  /* __HAVE_LIMITATION__ */


#ifdef  __HAVE_TURBO__
	/* Sanitizing TURBO mode. */
	if((o.turbo) && !(o.flood)){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr, "%s(): Turbo mode is only available with flood mode\n", __FUNCTION__);
		fflush(stderr);
		return(0);
	}
#endif  /* __HAVE_TURBO__ */

#ifdef  __HAVE_T50__
	/* Sanitinzing the threshold. */
	if((o.ip.protocol == IPPROTO_T50) && (o.threshold < T50_THRESHOLD_MIN)){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		fprintf(stderr, "%s(): Protocol %s cannot have threshold smaller than %d\n", __FUNCTION__, protocols[o.ip.protoname], T50_THRESHOLD_MIN);
		fflush(stderr);
		return(0);
	}
#endif  /* __HAVE_T50__ */

	/* Warning FLOOD mode. */
	if(o.flood){
		fprintf(stdout, "%s entering in FLOOD", program);
#ifdef  __HAVE_TURBO__
		/* Warning TURBO mode. */
		if(o.turbo)
			fprintf(stdout, "+[TURBO]");
#endif  /* __HAVE_TURBO__ */
		fprintf(stdout, " mode, please, hit Ctrl+C (^C) to stop!\n\a");
		fflush(stdout);
	}

	/* Returning. */
	return(1);
}
#endif  /* CHECK_C__ */
