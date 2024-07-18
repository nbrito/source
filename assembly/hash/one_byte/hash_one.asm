;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Talk:        The Departed - Exploit Next Generation (The Philosophy)
; Author:      Nelson Brito <nbrito *NoSPAM* protonmail.com>
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
IFNDEF    HASH_ONE_ASM__
          HASH_ONE_ASM__    equ    <1>

.686

.MODEL FLAT, STDCALL
OPTION  CASEMAP:NONE;, PROLOGUE:NONE, EPILOGUE:NONE

.CODE

hash_one PROC function_name:DWORD
	start:
		xor		edx, edx
		mov		esi, function_name
		cdq
	hash_one_calculate:
		lodsb
		xor		al, 71h
		sub		dl, al
		cmp		al, 71h
		jne		hash_one_calculate
	hash_one_done:
		mov		eax, edx
		ret
hash_one ENDP

.DATA

ELSE
	echo Sorry! Duplicate assembly component hash_one.asm!
ENDIF

END
