/**************************************************************************
 * Talk:        Inception - The extended edition
 * Author:      Nelson Brito <nbrito *NoSPAM* sekure.org>
 * Conference:  Hackers to Hackers Conference Eighth Edition (October 2011)
 **************************************************************************
 *         .___                            __  .__                        *
 *         |   | ____   ____  ____ _______/  |_|__| ____   ____           *
 *         |   |/    \_/ ___\/ __ \\____ \   __\  |/  _ \ /    \          *
 *         |   |   |  \  \__\  ___/|  |_> >  | |  (  <_> )   |  \         *
 *         |___|___|__/\_____>_____>   __/|__| |__|\____/|___|__/         *
 *                                 |__|                                   *
 *                     _______________  ____ ____                         *
 *                     \_____  \   _  \/_   /_   |                        *
 *                      /  ____/  /_\  \|   ||   |                        *
 *                     /       \  \_/   \   ||   |                        *
 *                     \________\_______/___||___|                        *
 *                                                                        *
 **************************************************************************
  Copyright (c) 2011 Nelson Brito. All rights reserved worldwide.
 
  This program is free software: you can redistribute it and/or modify it
  under  the terms of the GNU General Public License  as published by the
  Free Software Foundation,  either version 3 of the License, or (at your
  option) any later version.

  This program  is  distributed in  the hope that  it will be useful, but
  WITHOUT  ANY  WARRANTY;   without   even  the   implied   warranty   of
  MERCHANTABILITY  or  FITNESS  FOR  A  PARTICULAR  PURPOSE.  See the GNU
  General Public License for more details.

  You  should have  received a copy of the  GNU  General  Public  License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ***************************************************************************/
#ifndef __TRANFERTODESTINATION_CXX__
#define __TRANFERTODESTINATION_CXX__ 1

#define TranferFromSrc          "CXfer::TransferFromSrc(void)"
#define TransfertoDestination   "CRecordInstance::TransferToDestination(void)"

int CRecordInstance::TransferToDestination () {
    int ebp_minus_4h, eax;
    int esi, ebx = 0;
    
    esi = (sizeof(edi) >> 2) - 1;

    ebp_minus_4h = ebx;
    
    do{
        if(edi[ebx] == 0) continue;

        eax = edi[ebx]->TransferFromSrc();

        if((ebp_minus_4h == 0) && (eax != 0))
            ebp_minus_4h = eax;

        ebx++;
    }while(ebx <= esi);

    return(ebp_minus_4h);
}
#endif
