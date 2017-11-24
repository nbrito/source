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
#ifndef __OPTIONS_H
#define __OPTIONS_H 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: options.h,v 1.9 2008-09-11 10:49:07-03 nbrito Exp $ */
#include "common.h"

__BEGIN_DECLS

/* A little ASCII Art Banner. Remeber the BBS??? */
#define __ENG_ASCII_BANNER  "\n\t\t\t  ,,,   '#,:#$#.   ,,,\n\t\t\t.#' `,  :#  " \
			    " '#; .#'  `,\n\t\t\t##,,.'  $#    '# ##.  ,#\n\t\t" \
			    "\t'#:.,' ,:'   ,#' '#:.,#:\n\t\t\t                " \
			    "     ##\"\n\t\t\t                 .  ##'\n\t\t\t  " \
			    "                ````\n\n"
static int8_t * banner    = __ENG_ASCII_BANNER;
static int8_t * program   = "eng";

#ifdef  OPTIONS_C__
/* XXX - Internal declarations. */

#include <getopt.h>

extern int    optind;
extern char * optarg;

/* Copyright information. */
#define DISCLOSURE_WARNING  "This code is *CONFIDENCIAL, PROPRIETARY and PROTECTED*  f" \
			    "rom disclosure.\nNeeds to be notified to Nelson Brito, in" \
			    " the case of this  code is being\ndistributed or publishe" \
			    "d in any way.\n\n"
static int8_t * author    = "Nelson Brito";
static int8_t * email     = "nbrito@sekure.org";
static int8_t * copyright = "ENG v"__MAJOR_VERSION"."__MINOR_VERSION" Copyright© 2004" \
			    "-2008 Nelson Brito.\n\n"DISCLOSURE_WARNING"Modified Alph" \
			    "a2.c Code - "__ALPHA2_COPYRIGHT ".\n";

#else   /* OPTIONS_C__ */

/* XXX - External declarations. */

#endif  /* OPTIONS_C__ */

__END_DECLS

#endif  /* __OPTIONS_H */
