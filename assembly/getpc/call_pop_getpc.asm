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
IFNDEF	CALL_POP_GETPC_ASM__
	CALL_POP_GETPC_ASM__	equ	<1>
.686

.MODEL FLAT, STDCALL
OPTION  CASEMAP:NONE;, PROLOGUE:NONE, EPILOGUE:NONE

.CODE

call_pop_getpc PROC
	start:
		jmp		trampoline
	setup_getpc:
		pop		eax
		jmp		assembly
	trampoline:
		call		setup_getpc
	assembly:
call_pop_getpc ENDP

.DATA

ELSE
	echo Sorry! Duplicate assembly component file call_pop_getpc.asm!
ENDIF

END
