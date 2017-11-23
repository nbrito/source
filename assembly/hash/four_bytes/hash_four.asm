;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Talk:        The Departed - Exploit Next Generation (The Philosophy)
; Author:      Nelson Brito <nbrito *NoSPAM* sekure.org>
; Conference:  Hackers to Hackers Conference Sixth Edition (November 2009)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Copyright (c) 2009 Nelson Brito. All rights reserved worldwide.
;
; This program is free software: you can redistribute it and/or modify it
; under  the terms of the GNU General Public License  as published by the
; Free Software Foundation,  either version 3 of the License, or (at your
; option) any later version.
;
; This program  is  distributed in  the hope that  it will be useful, but
; WITHOUT  ANY  WARRANTY;   without   even  the   implied   warranty   of
; MERCHANTABILITY  or  FITNESS  FOR  A  PARTICULAR  PURPOSE.  See the GNU
; General Public License for more details.
;
; You  should have  received a copy of the  GNU  General  Public  License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
IFNDEF    HASH_FOUR_ASM__
          HASH_FOUR_ASM__    equ    <1>
.686

.MODEL FLAT, STDCALL
OPTION  CASEMAP:NONE;, PROLOGUE:NONE, EPILOGUE:NONE

.CODE

Right_Rotation_Without_NULL		equ		<1>
Left_Rotation_Without_NULL		equ		<0>
Right_Rotation_With_NULL		equ		<0>
Left_Rotation_With_NULL			equ		<0>

hash_four PROC function_name:DWORD
	start:
		xor		esi, esi
		mov		esi, function_name
		xor		edi, edi
		cld
	hash_four_calculate:
		xor		eax, eax
		lodsb
		.IF		Right_Rotation_Without_NULL
			cmp		al, ah
			je		hash_four_done
			ror		edi, 13
			add		edi, eax
		.ELSEIF	Left_Rotation_Without_NULL
			cmp		al, ah
			je		hash_four_done
			rol		edi, 7
			xor		edi, eax
		.ELSEIF	Right_Rotation_With_NULL
			ror		edi, 13
			cmp		al, ah
			je		hash_four_done
			add		edi, eax
		.ELSEIF Left_Rotation_With_NULL
			rol		edi, 7
			cmp		al, ah
			je		hash_four_done
			xor		edi, eax
		.ENDIF
		jmp		hash_four_calculate
	hash_four_done:
		mov		eax, edi
		ret		4
hash_four ENDP

.DATA

ELSE
	echo Sorry! Duplicate assembly component hash_four.asm!
ENDIF

END
