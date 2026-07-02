# Top-level dispatcher for VanMoof S6 firmware decompilations.
#
# Each target lives in its own subdirectory with its own Makefile. This file is
# a thin forwarder so you can run `make <target>` from the repo root. No target
# is "active" yet — nothing is reconstructed; `make` prints the target list.
#
# NOTE: motor_control is expected to be a TI C2000 DSP, not an arm-none-eabi
# target — its subdir Makefile is a placeholder until the toolchain is settled.

WARES := ble modem handlebar elock power_control motor_sensor \
         frontlight rearlight charger motor_control

.PHONY: all help clean $(WARES) all-wares

all: help

help:
	@echo "VanMoof S6 decomp — no active target yet."
	@echo "Targets (per-subdir compile gate):"
	@echo "  $(WARES)"
	@echo "Usage:"
	@echo "  make <target>   — build one target's subdir"
	@echo "  make all-wares  — build every scaffolded target"
	@echo "  make clean      — clean every target"

$(WARES):
	$(MAKE) -C $@

all-wares: $(WARES)

clean:
	@for w in $(WARES); do [ -f $$w/Makefile ] && $(MAKE) -C $$w clean || true; done
