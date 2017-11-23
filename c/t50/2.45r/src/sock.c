/* 
 * $Id: sock.c,v 3.4 2010-11-27 14:48:12-02 nbrito Exp $
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
#ifndef SOCK_C__
#define SOCK_C__ 1

#include <common.h>


/* Local Global Variables. */
#ifdef  __HAVE_DEBUG__
/* Revision Control System. */
static int8_t * revision = "$Revision: 3.4 $";
#endif  /* __HAVE_DEBUG__ */


/* Function Name: Socket configuration.

   Description:   This function configures the socket(s).

   Targets:       N/A */
socket_t sock(void){
	/* Socket. */
	static socket_t fd;
	static u_int32_t n = 1, len;
	static u_int32_t *nptr = &n;

	/* Setting SOCKET RAW. */
	if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	/* Setting IP_HDRINCL. */
	if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, nptr, sizeof(n)) < 0){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}

/* Taken from libdnet by Dug Song. */
#ifdef  SO_SNDBUF
	len = sizeof(n);

	/* Getting SO_SNDBUF. */
	if(getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, &len) < 0){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		perror("getsockopt()");
		exit(EXIT_FAILURE);
	}

	for(n += 128 ; n < 1048576 ; n += 128){
		/* Setting SO_SNDBUF. */
		if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, len) < 0){
			if(errno == ENOBUFS)
				break;
#ifdef  __HAVE_DEBUG__
			ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
			perror("setsockopt()");
			exit(EXIT_FAILURE);
		}
	}

#endif  /* SO_SNDBUF */

#ifdef  SO_BROADCAST
	/* Setting SO_BROADCAST. */
	if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, nptr, sizeof(n)) < 0){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}
#endif  /* SO_BROADCAST */

#ifdef  SO_PRIORITY
	/* Setting SO_BROADCAST. */
	if(setsockopt(fd, SOL_SOCKET, SO_PRIORITY, nptr, sizeof(n)) < 0){
#ifdef  __HAVE_DEBUG__
		ERR_DDEBUG(revision);
#endif  /* __HAVE_DEBUG__ */
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}
#endif  /* SO_PRIORITY */

	return(fd);
}
#endif  /* SOCK_C__ */
