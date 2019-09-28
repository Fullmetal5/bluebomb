# Copyright 2019  Dexter Gerig  <dexgerig@gmail.com>
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


CFLAGS := -Wall -W -Os -ffreestanding -std=gnu99 -Wstrict-aliasing=2 \
	-mno-eabi -mno-sdata -mcpu=750


apps := $(wildcard ./*.lds)
targets := $(apps:.lds=.bin)



ifeq ($(V),1)
	Q :=
else
	Q := @
	MAKEFLAGS += --no-print-directory
endif


all: stage0.o $(targets)

$(targets): %.bin: %.elf
	@echo "  OBJCOPY   $@"
	$(Q)$(OBJCOPY) -O binary $< $@

elfs := $(targets:.bin=.elf)
$(elfs): %.elf: %.lds
	@echo "  LINK      $@"
	$(Q)$(LD) $(LDFLAGS) -n -T $^ -o $@

stage0.o: %.o: %.s
	@echo "  ASSEMBLE  $@"
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f stage0.o $(targets) $(elfs)
