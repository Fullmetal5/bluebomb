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

OUTPUT_FORMAT("elf32-powerpc")
OUTPUT_ARCH(powerpc:common)

ENTRY(_start)

SECTIONS {
	/* Adjust app specific settings here. */
	sdp_cb = 0x81159340;
	l2cb = 0x81158740;
	switch_addr = 0x815f7d80;
	switch_break = 0x8152e2a0;
	payload_addr = 0x80004000;
	
	. = (0x80001800 - 0xc);
	dest = (. + 0xc);
	.app_settings : {
		LONG(sdp_cb)
		LONG(l2cb)
		LONG(switch_addr)
	}

	.start : {
		stage0.o(*)
	}
}

