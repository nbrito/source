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
#ifndef __ENG_H
#define __ENG_H 1
/* Nelson Brito <nbrito@sekure.org>
   $Id: eng.h,v 1.6 2008-09-14 12:56:08-03 nbrito Exp $ */
#include <signal.h>
#include "common.h"

__BEGIN_DECLS

#ifdef  ENG_C__
/* XXX - Internal declarations. */

#ifdef  __HAVE_LYRICS__
/* XXX - Internal declarations. */

/* Those are incredible hits. */
u_int8_t * lyrics [3] = {
	/* Jay Z & Linkin Park's Numb vs Encore lyrics - Pice #01. */
	"...\nNow can I get an encore, do you want more\nCookin r"
	"aw with the Brooklyn boy\nSo for one last time I need y'"
	"all to roar\n\nNow what the hell are you waitin for\nAft"
	"er me, there shall be no more\nSo for one last time, nig"
	"ga make some noise\n...\n\t\tJay Z vs Linkin Park (Colli"
	"sion Course Album)\n\n",

	/*Jay Z & Linkin Park's Numb vs Encore lyrics - Pice #02. */
	"...\nWho you know fresher than Hov\'? Riddle me that\nThe"
	" rest of y\'all know where I\'m lyrically at\nCan\'t none"
        "of y\'all mirror me back\nYeah hearin me rap is like hear"
	"in G. Rap in his prime\nI\'m, young H.O., rap\'s Grateful"
        " Dead\nBack to take over the globe, now break bread\nI\'m"
	" in, Boeing jets, Global Express\nOut the country but the"
        " blueberry still connect\nOn the low but the yacht got a "
	"triple deck\nBut when you Young, what the fuck you expect"
	"? Yep, yep\nGrand openin, grand closin\nGod damn your man"
       	" Hov\' cracked the can open again\nWho you gon\' find dop"
	"er than him with no pen\njust draw off inspiration\nSoon "
	"you gon\' see you can\'t replace him\nwith cheap imitatio"
	"ns for DESE GENERATIONS\n...\n\t\tJay Z vs Linkin Park (C"
	"ollision Course Album)\n\n",
	
	/* Jay Z & Linkin Park's Numb vs Encore lyrics - Pice #03. */
	"...\nI\'ve become so numb\nCan I get an encore, do you w"
	"ant more (more...)\nI\'ve become so numb\nSo for one las"
	"t time I need y\'all to roar\nOne last time I need y\'al"
	"l to roar\n...\n\t\tJay Z vs Linkin Park (Collision Cour"
	"se Album)\n\n",
};

#else   /* __HAVE_LYRICS__ */
/* XXX - External declarations. */

u_int8_t *    done = "are you ready to write 1,745,353,423,278,04"
		     "7,232 new IPS signatures?\n";

#endif  /* __HAVE_LYRICS__ */

u_int8_t * warning = "trying to connect the bind shell... ";

#else   /* ENG_C__ */
/* XXX - External declarations. */

#endif  /* ENG_C__ */

__END_DECLS

#endif  /* __ENG_H */
