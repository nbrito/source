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
#ifndef __OPTIONS_H
#define __OPTIONS_H 1

/* Nelson Brito <nbrito@sekure.org>
   $Id: options.h,v 1.2 2008-08-23 10:10:07-03 nbrito Exp $ */
#include "common.h"

__BEGIN_DECLS

#ifdef  OPTIONS_C__
/* XXX - Internal declarations. */

#ifndef _GETOPT_H
/* XXX - Internal declarations. */

#include "getopt.h"

#else   /* _GETOPT_H */
/* XXX - External declarations. */

#include <getopt.h>

#endif  /* _GETOPT_H */

extern int    optind;
extern char * optarg;

/* Copyright information. */
static int8_t * program   = "b52";
static int8_t * author    = "Nelson Brito";
static int8_t * email     = "nbrito@sekure.org";
static int8_t * copyright = "This code is *CONFIDENCIAL, PROPRIETARY and PROTECTED*  f"
			    "rom disclosure.\nNeeds to be notified to Nelson Brito, in"
			    " the case of this  code is being\ndistributed or publishe"
			    "d in any way.\n\n";


#else   /* OPTIONS_C__ */
/* XXX - External declarations. */

#endif  /* OPTIONS_C__ */

__END_DECLS

#endif  /* __OPTIONS_H */
