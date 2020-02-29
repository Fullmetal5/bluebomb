# Copyright 2019-2020  Dexter Gerig  <dexgerig@gmail.com>
# Copyright 2008-2009  Segher Boessenkool  <segher@kernel.crashing.org>
# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

CROSS ?= powerpc-eabi-


ifeq ($(origin CC), default)
	CC := $(CROSS)gcc -m32
endif
ifeq ($(origin LD), default)
	LD := $(CROSS)ld
endif
OBJCOPY ?= $(CROSS)objcopy


CFLAGS := -Wall -W -O2 -ffreestanding -std=gnu99 -Wstrict-aliasing=2 \
	-mno-eabi -mno-sdata -mcpu=750


targets := stage0.bin

objs := stage0.o


ifeq ($(V),1)
	Q :=
else
	Q := @
	MAKEFLAGS += --no-print-directory
endif


all: $(targets)
	@echo "  XXD       stage0.bin"
	$(Q)xxd -i stage0.bin stage0_bin.h
	$(Q)cp stage0_bin.h ..

$(targets): %.bin: %.elf
	@echo "  OBJCOPY   $@"
	$(Q)$(OBJCOPY) -O binary $< $@

elfs := $(targets:.bin=.elf)
$(elfs): %.elf: %.lds $(objs)
	@echo "  LINK      $@"
	$(Q)$(LD) $(LDFLAGS) -n -T $^ -o $@

%.o: %.s
	@echo "  ASSEMBLE  $@"
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

FORCE:

clean:
	rm -rf $(objs) $(targets) $(elfs) stage0_bin.h
