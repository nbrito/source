;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Talk:        Inception - The extended edition
; Author:      Nelson Brito <nbrito *NoSPAM* sekure.org>
; Conference:  Hackers to Hackers Conference Eighth Edition (October 2011)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;         .___                            __  .__                        ;;
;         |   | ____   ____  ____ _______/  |_|__| ____   ____           ;;
;         |   |/    \_/ ___\/ __ \\____ \   __\  |/  _ \ /    \          ;;
;         |   |   |  \  \__\  ___/|  |_> >  | |  (  <_> )   |  \         ;;
;         |___|___|__/\_____>_____>   __/|__| |__|\____/|___|__/         ;;
;                                 |__|                                   ;;
;                     _______________  ____ ____                         ;;
;                     \_____  \   _  \/_   /_   |                        ;;
;                      /  ____/  /_\  \|   ||   |                        ;;
;                     /       \  \_/   \   ||   |                        ;;
;                     \________\_______/___||___|                        ;;
;                                                                        ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Copyright (c) 2011 Nelson Brito. All rights reserved worldwide.
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
IFNDEF	__TRANFERTODESTINATION_ASM__
		__TRANFERTODESTINATION_ASM__	equ	<1>
.686

.MODEL	FLAT, STDCALL
OPTION	CASEMAP:NONE
INCLUDE		\MASM32\INCLUDE\WINDOWS.INC
INCLUDE		\MASM32\INCLUDE\USER32.INC
INCLUDE		\MASM32\INCLUDE\KERNEL32.INC
INCLUDELIB	\MASM32\LIB\USER32.LIB
INCLUDELIB	\MASM32\LIB\KERNEL32.LIB

.DATA	?

.DATA
TransferFromSrc			db	"CXfer::TransferFromSrc()", 0
TransferToDestination	db 	"CRecordInstance::TransferToDestination()", 0

.CODE
TransferToDestination@CRecordInstance PROC NEAR USES EAX ECX EBX EDI ESI EBP ESP
start:
mov		edi, edi					;; make sure 'edi' will be saved
push	ebp							;; save the value of 'ebp'
mov		ebp, esp					;; 'ebp' points to the top of the stack
push	ecx							;; save the value of 'ecx'
push	ebx							;; save the value of 'ebx'
push	esi							;; save the value of 'esi'
push	edi							;; save the value of 'edi'
mov		edi, ecx					;; 'ecx' is 'Array' pointer
									;;  - pointer is moved to 'edi'
mov		esi, [edi+08h]				;; '[edi+08h]' is the 'Array' size
									;;  - size is moved to 'esi'
xor		ebx, ebx					;; 'ebx' is the 'Counter' for 'do_while' 'Loop'
									;;  - xoring 'ebx' the value will be 0
shr		esi, 02h					;; 'esi' is shifted right 2 bits
									;;  - a good explanation is:
									;;   - 16      = 0Ch = 0000 0000 0001 0000 = 16
									;;   - 16 >> 2 = 04h = 0000 0000 0000 0100 = 4
									;;  - this operation is very similar to:
									;;   - int _arX[x] = { 1, 2, 3, 4, ..., x };
									;;   - int _szX = sizeof(_arX)/sizeof(*_arX);
									;;   - or 'Array.Size()'
									;;   - or 'std::array::size' method
dec		esi							;; IF 'esi' decremented < 0
									;;  - this operation is very similar to:
									;;   - int _arX[x] = { 1, 2, 3, 4, ..., x };
									;;   - int _szX = (sizeof(_arX)/sizeof(*_arX));
                                    ;;   - _szX -= 1;
									;;   - or 'Array.Size() - 1'
									;;  - 'esi' is the 'Array Index'
mov		dword ptr [ebp-04h], ebx	;; 'ebx' as the '[ebp-04h]'
js		return						;; THEN 'return'
									;; ELSE
do_while:							;; 'do_while'
									;;  - there is more to do
mov		eax, [edi+0Ch]				;; '[edi+0Ch]' is the 'Array Elements' pointer
									;;  - pointer is moved to 'eax'
cmp		dword ptr [eax+ebx*04h], 0	;; IF 'Array Element' == 0
									;;  - a good explanation is:
									;;	 - each 'Loop' increments 'Counter'
									;;    - #1: 'ebx' is 0 and 'eax' is 12345678h
									;;     - 'Array Element' is (12345678h+(0*4))
									;;     - or 1234567Ch
									;;    - #2: 'ebx' is 1 and 'eax' is 12345678h
									;;     - 'Array Element' is (12345678h+(1*4))
									;;     - or 12345680h
je		continue					;; THEN 'continue'
									;; ELSE
mov		ecx, [eax+ebx*04h]			;; '[eax+ebx*04h]' is the 'Array Element' pointer
									;;  - pointer is moved to 'ecx'
call	TransferFromSrc@CXfer		;; call 'CXfer::TransferFromSrc()'
test	eax, eax					;; IF 'eax' == 0
									;;  - 'eax' modified by 'CXfer::TransferFromSrc()'
je		continue					;; THEN 'continue'
									;; ELSE
cmp		dword ptr [ebp-04h], 0		;; IF '[ebp-04h]' != 0
									;;  - '[ebp-04h]' already has 0
									;;  - 'mov dword ptr [ebp-04h], ebx'
									;;  - a good explanation is:
									;;	 - each 'Loop' increments 'Counter'
									;;    - #1: '[ebp-04h]' is 0
									;;     - THEN 'continue'
									;;    - #2: '[ebp-04h]' is 1
									;;     - ELSE 'mov dword ptr [ebp-04h], eax'
									;;   - 0 seens to be OK and anything else NOT OK
jne		continue					;; THEN 'continue'
									;; ELSE
mov		dword ptr [ebp-04h], eax	;; 'eax' as the '[ebp-04h]'
continue:							;; 'continue'
									;;  - whether there is nothing or more to do
inc		ebx							;; increment the 'Counter'
cmp		ebx, esi					;; IF 'Counter' <= 'Array Index'
									;;  - a good explanation for MS08-078 is:
									;;   - since the 'Array' has been freed
									;;   - the 'Array Elements' have been destroyed
									;;   - the '[edi+08h]' has been updated
									;;   - but 'Array Index' (esi) hasn't been
jle		do_while					;; THEN 'do_while'
									;; ELSE
return:								;; 'return'
									;;  - there is nothing to do
mov		eax, dword ptr [ebp-04h]	;; 'eax' points to the '[ebp-04h]'
pop		edi							;; 'edi' is 'Array' pointer
pop		esi							;; 'esi' is 'Array Index'
pop		ebx							;; 'ebx' is 'Counter' or 'Array Elements'
leave								;; destroy current stack frame
									;;  - restore the previous frame
ret									;; guess what? ;) 
stop:
TransferToDestination@CRecordInstance ENDP
align	8
ELSE
	echo Sorry! Duplicate assembly component file TransferToDestination.asm!
ENDIF
END
