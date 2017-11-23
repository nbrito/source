/**************************************************************************
 * Author:      Nelson Brito <nbrito *NoSPAM* sekure.org>
 ***************************************************************************
 * Copyright (c) 2010 Nelson Brito. All rights reserved worldwide.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under  the terms of the GNU General Public License  as published by the
 * Free Software Foundation,  either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program  is  distributed in  the hope that  it will be useful, but
 * WITHOUT  ANY  WARRANTY;   without   even  the   implied   warranty   of
 * MERCHANTABILITY  or  FITNESS  FOR  A  PARTICULAR  PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You  should have  received a copy of the  GNU  General  Public  License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **************************************************************************/
#include <stdio.h>

int main(void){
	int __12345[5] = {1,2,3,4,5}, i, c;
	int s[5], __54321 = sizeof(s)/sizeof(int);

	i = c = 0;

	/* Inverting the integer ordering. */
	while(i++ <__54321)
		/* @nbrito -- Tuesday  5 October 2010
		 *
		 * Here is the deal:
		 *   - 'vector[element]' == 'element[vector]'.
		 *
		 * So, in this case:
		 *   - '__12345[__54321 -i]' == '__54321[__12345 - i]'.
		 */
		i[s] =__54321[__12345 - i];
	while(c++ <__54321)
		printf("%i", c[s]);
	printf("\n");
}
