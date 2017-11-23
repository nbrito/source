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
#ifndef __OPTIONS_H
#define __OPTIONS_H 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: options.h,v 1.1 2008-09-13 13:42:46-03 nbrito Exp $ */
#include "common.h"

__BEGIN_DECLS

/* A little ASCII Art Banner. Remeber the BBS??? */
#define __NNG_ASCII_BANNER  "\n\t\t\t '#,:#$#.  '#,:#$#.    ,,,\n\t\t\t" \
			    "  :#   '#;  :#   '#; .#'  `,\n\t\t\t  $#  " \
			    "  '#  $#    '# ##.  ,#\n\t\t\t ,:'   ,#' ," \
			    ":'   ,#' '#:.,#:\n\t\t\t                  " \
			    "       ##\"\n\t\t\t                     . " \
			    " ##'\n\t\t\t                      ````\n\n"
static int8_t * banner = __NNG_ASCII_BANNER;

#ifdef  OPTIONS_C__
/* XXX - Internal declarations. */

#include <getopt.h>

extern int    optind;
extern char * optarg;

/* Copyright information. */
static int8_t * program   = "nng";
static int8_t * author    = "Nelson Brito";
static int8_t * email     = "nbrito@sekure.org";
static int8_t * copyright = "NNG v"__MAJOR_VERSION"."__MINOR_VERSION" Copyright© 2004" \
			    "-2008 Nelson Brito.\n";

#else   /* OPTIONS_C__ */
/* XXX - External declarations. */

#endif  /* OPTIONS_C__ */

__END_DECLS

#endif  /* __OPTIONS_H */
