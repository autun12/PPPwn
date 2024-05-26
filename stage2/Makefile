TARGET = stage2
OBJS = start.o stage2.o proc_utils.o utils.o

CC = gcc
OBJCOPY = objcopy
CFLAGS = -DSMP -isystem ../freebsd-headers/include -Wl,--build-id=none -Os -fno-stack-protector -Wno-int-conversion -Wno-incompatible-pointer-types  -fpic -fpie
LDFLAGS = -T linker.ld -nostartfiles -nostdlib

ifneq ($(filter $(FW), 750 751 755 800 801 803 850 852 900 903 904 950 951 960 1000 1001 1050 1070 1071 1100),)
CFLAGS += -DFIRMWARE=$(FW)
else
$(error "Invalid firmware")
endif

ifdef ENABLE_DEBUG_MENU
CFLAGS += -DENABLE_DEBUG_MENU=1
CFLAGS += -UUSB_LOADER
endif

ifdef MODULE_DUMPER
CFLAGS += -DUSB_LOADER=1
CFLAGS += -DMODULE_DUMPER=1
CFLAGS += -UENABLE_DEBUG_MENU
endif

ifdef USB_LOADER
CFLAGS += -DUSB_LOADER=1
CFLAGS += -UMODULE_DUMPER
CFLAGS += -UENABLE_DEBUG_MENU
endif

all: $(TARGET).bin

%.bin: %.elf
	$(OBJCOPY) -S -O binary $^ $@

$(TARGET).elf: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.asm
	$(CC) -x assembler-with-cpp -c $< -o $@
	
clean:
	@rm -f $(TARGET).bin $(TARGET).elf $(OBJS)