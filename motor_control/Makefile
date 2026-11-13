# motor_control - VanMoof S6 BLDC/FOC motor controller firmware (reconstruction).
#
# MCU: STM32G4 (Cortex-M4F, FPv4-SP-D16, hard-float), MCUboot image, Ghidra base
# 0x08002000 (see docs/hardware.md). Not the S5's TI C2000: an arm-none-eabi target.
#
# Only the VanMoof application layer is translated to C (see docs/progress.md);
# vendor code (CMSIS, SEGGER RTT, libgcc) is satisfied at link time. Default target
# is the per-translation-unit compile gate: every src/*.c must build clean with
# -Wall -Wextra -Wpedantic.

PROJECT      := motor_control
MCU          ?= cortex-m4
FPU          ?= fpv4-sp-d16
FLOAT_ABI    ?= hard
TOOLCHAIN    := arm-none-eabi-

CC           := $(TOOLCHAIN)gcc
OBJCOPY      := $(TOOLCHAIN)objcopy
OBJDUMP      := $(TOOLCHAIN)objdump
SIZE         := $(TOOLCHAIN)size

BUILD_DIR    := build
SRC_DIR      := src
INC_DIR      := include

OEM_IMAGE    ?= motor-control.bin

C_SRCS       := $(wildcard $(SRC_DIR)/*.c)
OBJS         := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(C_SRCS))
DEPS         := $(OBJS:.o=.d)

ARCH_FLAGS   := -mcpu=$(MCU) -mthumb -mfpu=$(FPU) -mfloat-abi=$(FLOAT_ABI)

CFLAGS       := $(ARCH_FLAGS) \
                -std=c11 \
                -Os -g3 \
                -ffunction-sections -fdata-sections \
                -fno-common -fno-builtin \
                -Wall -Wextra -Wpedantic -Wshadow \
                -Wno-unused-parameter \
                -I$(INC_DIR) \
                -MMD -MP

.PHONY: all clean size disasm help
.DEFAULT_GOAL := all

# Default: the compile gate — build every TU to an object, clean.
all: $(OBJS)
	@if [ -z "$(strip $(OBJS))" ]; then \
		echo "motor_control: no sources in $(SRC_DIR)/ yet."; \
	else \
		echo "motor_control: compiled $(words $(OBJS)) translation unit(s) clean."; \
	fi

$(BUILD_DIR):
	@mkdir -p $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

size: $(OBJS)
	@$(SIZE) $(OBJS)

disasm: $(OBJS)
	@for o in $(OBJS); do $(OBJDUMP) -d -S $$o; done > $(BUILD_DIR)/$(PROJECT).lst
	@echo "wrote $(BUILD_DIR)/$(PROJECT).lst"

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "Targets: all (compile gate, default), size, disasm, clean"
	@echo "Variables: MCU=$(MCU)"

-include $(DEPS)
