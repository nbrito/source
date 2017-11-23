/**************************************************************************
 * Talk:        The Departed - Exploit Next Generation (The Philosophy)
 * Author:      Nelson Brito <nbrito *NoSPAM* sekure.org>
 * Conference:  Hackers to Hackers Conference Sixth Edition (November 2009)
 ***************************************************************************
 * Copyright (c) 2009 Nelson Brito. All rights reserved worldwide.
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
#ifndef MAIN_C__
#define MAIN_C__ 1

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

extern unsigned long __stdcall hash_one(unsigned char * FuncName);

int main (int argc, char **argv){
	unsigned char *FuncName;
	unsigned long Hash;

	printf("Exploit Next Generation [Windows Function Hashing]\n");
	printf("Nelson Brito <nbrito[at]sekure.org>\n\n");

	if(argc == 2){
		FuncName = argv[1];

		printf("%s (one byte hash value) => ", FuncName);

		Hash = hash_one(FuncName);
		printf("%.2Xh\n", Hash);

		exit(1);
	} else {
		printf("use:     hash_one.exe [FunctionName]\n");
		printf("example: hash_one.exe  LoadLibraryA\n");
		exit(0);
	}
}
#endif
