# 32-bit ARM builds of the ChaCha20 / Ascon study, run under qemu-arm (no boards).
#
#   make -C chacha_ascon/arm TARGET=m4 test     KATs under qemu-arm -cpu cortex-m4
#   make -C chacha_ascon/arm TARGET=a7 test     KATs under qemu-arm -cpu cortex-a7
#   make -C chacha_ascon/arm TARGET=m4 cycles   trace-driven cycle estimate -> results/arm/
#
# The test binaries are the same tests/test_ca.c (all three KAT files, every
# placement/lane count) and tests/test_bc.c (AES-128-CTR, Qalqan-CTR) as on x86,
# linked with newlib's semihosting runtime
# (rdimon), which qemu's user-mode emulator services. -cpu cortex-m4 makes qemu
# reject any instruction an M4 does not have.
TARGET ?= m4
# Cortex-M4 block-cipher CTR kernels (m4 and m4hw): the adapted Schwabe-Stoffelen
# AES (third_party_m4/aes-armcortexm, CC0) and the Qalqan Thumb-2 kernels
M4_BC_SRC := src/aes/aes128_m4ss.c
M4_BC_ASM := src/aes/aes128_ctr_m4ss.S src/aes/aes128_ctr_m4ss_sram.S src/aes/aes128_ctr_m4ss_loop.S \
             src/aes/aes128_ctr_m4ss_loop_sram.S src/aes/aes128_ctr_m4ss_bs.S \
             src/aes/aes256_ctr_m4ss_loop.S src/aes/aes256_ctr_m4ss_loop_sram.S
# Accelerated Qalqan kernels (unrolled C, Thumb-2 asm) are not distributed (.gitignore);
# when present they are built and registered, otherwise only the reference.
QALQAN_ARM := $(wildcard ../src/qalqan/qalqan_cfast.c)
QALQAN_M4  := $(if $(QALQAN_ARM),$(wildcard ../src/qalqan/qalqan_m4.c))
ifneq ($(QALQAN_M4),)
M4_BC_SRC += src/qalqan/qalqan_m4.c src/qalqan/qalqan_cfast.c
M4_BC_ASM += src/qalqan/qalqan_m4_core.S
M4_QDEFS  := -DHAVE_QALQAN_ARM -DHAVE_QALQAN_M4
endif
CC     := arm-none-eabi-gcc
LD     := arm-none-eabi-ld
OBJCOPY:= arm-none-eabi-objcopy
QEMU   ?= $(HOME)/.local/opt/root/usr/bin/qemu-arm
TOP    := ..
B      := $(TOP)/../build/ca/$(TARGET)
EXT    := $(TOP)/../third_party/ext
ASCONC := $(EXT)/ascon-c/crypto_aead/asconaead128

ifeq ($(TARGET),m4)
CPU      := -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
QCPU     := cortex-m4
DEFS     := -DCA_M4 $(M4_QDEFS)
ASCON_C_IMPLS := ref opt32 opt32_lowsize bi32 bi32_lowsize bi32_lowreg \
                 armv7m armv7m_small armv7m_lowsize bi32_armv7m bi32_armv7m_small
EXTRA_SRC := src/chacha/chacha20_m4.c $(M4_BC_SRC)
EXTRA_ASM := src/chacha/chacha20_m4_core.S $(M4_BC_ASM)
else ifeq ($(TARGET),m4hw)
# The real board (STM32F407): same sources and impl list as TARGET=m4, built
# with the board firmware's ABI (hard float) and function alignment, linked with
# fw/m4's startup/clock/semihosting code and newlib-nano. `make board` flashes
# it, runs the on-board KAT gate and the DWT timing (tools/m4_board.py).
CPU      := -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -ffunction-sections -falign-functions=16
QCPU     := cortex-m4
DEFS     := -DCA_M4 $(M4_QDEFS)
ASCON_C_IMPLS := ref opt32 opt32_lowsize bi32 bi32_lowsize bi32_lowreg \
                 armv7m armv7m_small armv7m_lowsize bi32_armv7m bi32_armv7m_small
EXTRA_SRC := src/chacha/chacha20_m4.c $(M4_BC_SRC)
EXTRA_ASM := src/chacha/chacha20_m4_core.S $(M4_BC_ASM)
else ifeq ($(TARGET),a7)
CPU      := -mcpu=cortex-a7 -marm -mfpu=neon-vfpv4 -mfloat-abi=hard
QCPU     := cortex-a7
DEFS     := -DCA_A7
ASCON_C_IMPLS := ref opt32 opt32_lowsize bi32 bi32_lowsize armv6 bi32_armv6 \
                 armv7m bi32_armv7m neon
EXTRA_SRC := src/chacha/chacha20_neon.c src/ascon/ascon_neon_multi.c
ifneq ($(QALQAN_ARM),)
EXTRA_SRC += src/qalqan/qalqan_cfast.c
DEFS      += -DHAVE_QALQAN_ARM
endif
# the *armv7m variants' inline asm is Thumb-2 only (ORN); the A7 runs Thumb-2
THUMB_IMPLS := armv7m bi32_armv7m
else
$(error TARGET must be m4, m4hw or a7)
endif

OPT    ?= -O2
CFLAGS := $(CPU) $(OPT) -std=gnu11 -Wall -Wextra -Wno-format-truncation $(DEFS) \
          -I$(TOP)/include -I$(TOP)/tests -I$(TOP)/src/qalqan
LIBS   := --specs=rdimon.specs

OWN_SRC := src/chacha/chacha20_ref.c src/chacha/chacha20_lazy.c src/ascon/ascon_common.c \
           src/ascon/ascon_scalar_multi.c src/registry_arm.c $(EXTRA_SRC) \
           src/aes/aes128_ref.c src/aes/aes128_ttable.c src/qalqan/qalqan.c src/qalqan/qalqan_ctr.c
OWN_OBJ := $(patsubst src/%.c,$(B)/%.o,$(OWN_SRC)) $(patsubst src/%.S,$(B)/%.o,$(EXTRA_ASM))
ASCON_OBJ := $(patsubst %,$(B)/ascon-c/%.o,$(ASCON_C_IMPLS))
LIST   := $(foreach v,$(ASCON_C_IMPLS),X($(v)))

# Every object depends on this stamp, rewritten only when the flags change, so
# a different OPT/CFLAGS can never leave stale code in a tested binary.
FLAGS_NOW := $(CC) $(CFLAGS) | $(OPT) | $(THUMB_IMPLS)
$(shell mkdir -p $(B); [ "$$(cat $(B)/.flags 2>/dev/null)" = '$(FLAGS_NOW)' ] || echo '$(FLAGS_NOW)' > $(B)/.flags)
STAMP := $(B)/.flags

all: $(B)/test_ca.elf $(B)/test_bc.elf $(B)/bench_arm.elf

$(B)/registry_arm.o: $(TOP)/src/registry_arm.c $(TOP)/include/*.h Makefile $(STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) '-DASCON_C_LIST=$(LIST)' -c $< -o $@

$(B)/%.o: $(TOP)/src/%.c $(TOP)/include/*.h $(STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(B)/%.o: $(TOP)/src/%.S $(wildcard $(TOP)/src/aes/*.S) $(STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CPU) -c $< -o $@

$(B)/ascon-c/%.o: $(ASCONC)/%/*.c $(ASCONC)/%/*.h $(STAMP)
	@mkdir -p $(B)/ascon-c/$*
	cd $(B)/ascon-c/$* && for f in $(abspath $(ASCONC))/$*/*.c; do \
	  $(CC) $(CPU) $(if $(filter $*,$(THUMB_IMPLS)),-mthumb) $(OPT) -std=gnu11 -I$(abspath $(ASCONC))/$* -I$(abspath $(EXT))/ascon-c/tests \
	    -c $$f -o $$(basename $$f .c).o || exit 1; done
	$(LD) -r -o $@.tmp $(B)/ascon-c/$*/*.o
	$(OBJCOPY) --keep-global-symbol=crypto_aead_encrypt --keep-global-symbol=crypto_aead_decrypt $@.tmp $@.tmp2
	$(OBJCOPY) --redefine-sym crypto_aead_encrypt=ascon_c_$*_encrypt \
	  --redefine-sym crypto_aead_decrypt=ascon_c_$*_decrypt $@.tmp2 $@
	rm -f $@.tmp $@.tmp2

$(B)/kat_data.c: $(TOP)/kat/*.txt $(TOP)/tools/embed_kats.py
	@mkdir -p $(B)
	python3 $(TOP)/tools/embed_kats.py $@

$(B)/test_ca.elf: $(TOP)/tests/test_ca.c $(TOP)/tests/kat_common.h $(B)/kat_data.c $(OWN_OBJ) $(ASCON_OBJ)
	$(CC) $(CFLAGS) $< $(B)/kat_data.c $(OWN_OBJ) $(ASCON_OBJ) $(LIBS) -o $@

$(B)/test_bc.elf: $(TOP)/tests/test_bc.c $(TOP)/tests/kat_common.h $(OWN_OBJ) $(ASCON_OBJ)
	$(CC) $(CFLAGS) $< $(OWN_OBJ) $(ASCON_OBJ) $(LIBS) -o $@

$(B)/bench_arm.elf: $(TOP)/bench/bench_arm.c $(TOP)/bench/ca_mark.c $(OWN_OBJ) $(ASCON_OBJ)
	$(CC) $(CFLAGS) $< $(TOP)/bench/ca_mark.c $(OWN_OBJ) $(ASCON_OBJ) $(LIBS) -o $@

test: $(B)/test_ca.elf $(B)/test_bc.elf
	$(QEMU) -cpu $(QCPU) $(B)/test_ca.elf
	$(QEMU) -cpu $(QCPU) $(B)/test_bc.elf
	touch $(B)/.kat-passed

# KAT gate: estimates are produced only from a build whose test binaries passed
$(B)/.kat-passed: $(B)/test_ca.elf $(B)/test_bc.elf
	$(QEMU) -cpu $(QCPU) $(B)/test_ca.elf
	$(QEMU) -cpu $(QCPU) $(B)/test_bc.elf
	touch $@

# Trace (one instruction per TB, every execution logged) and price it.
# The trace (~10^7 lines) is streamed through a FIFO, never stored.
OUTCSV = $(TOP)/results/arm/$(TARGET)$(SUFFIX)-cycles$(if $(ONLY),-$(ONLY)).csv
cycles: $(B)/bench_arm.elf $(B)/.kat-passed
	@mkdir -p $(TOP)/results/arm
	rm -f $(B)/trace.fifo && mkfifo $(B)/trace.fifo
	$(QEMU) -cpu $(QCPU) -one-insn-per-tb -d exec,nochain -D $(B)/trace.fifo $< $(ONLY) > $(B)/regions.txt & q=$$!; \
	python3 $(TOP)/tools/arm_cycles.py --core $(TARGET) --elf $< --trace $(B)/trace.fifo $(MODEL_FLAGS) \
	  --regions $(B)/regions.txt --csv $(OUTCSV).tmp; \
	st=$$?; wait $$q; qs=$$?; rm -f $(B)/trace.fifo; \
	if [ $$st -ne 0 ] || [ $$qs -ne 0 ]; then echo "model status $$st, qemu status $$qs"; rm -f $(OUTCSV).tmp; exit 1; fi; \
	mv $(OUTCSV).tmp $(OUTCSV)

# M4 only: the same, with the instruction-fetch-only flash + ART sensitivity
# model (5 wait states at 168 MHz; flash data reads are not modelled)
cycles-flash:
	$(MAKE) cycles MODEL_FLAGS=--flash-ws=5 SUFFIX=-flash

# ---- TARGET=m4hw: on-board firmware and run ----
FW     := $(TOP)/../fw/m4
FW_ELF := $(B)/ca_fw.elf
$(FW_ELF): $(TOP)/fw_m4/ca_fw_main.c $(TOP)/fw_m4/ca_m4.ld $(TOP)/tests/test_ca.c $(TOP)/tests/test_bc.c \
           $(TOP)/tests/kat_common.h \
           $(B)/kat_data.c $(OWN_OBJ) $(ASCON_OBJ) $(STAMP) Makefile \
           $(wildcard $(FW)/timing.h $(FW)/system_init.[ch] $(FW)/semihost.[ch] $(FW)/startup_stm32f407.s)
	$(CC) $(CFLAGS) -I$(FW) -Dmain=test_main -DKAT_LINE_MAX=4096 -DKAT_MAX_LEN=4097 -c $(TOP)/tests/test_ca.c -o $(B)/test_ca_fw.o
	$(CC) $(CFLAGS) -I$(FW) -Dmain=test_bc_main -c $(TOP)/tests/test_bc.c -o $(B)/test_bc_fw.o
	$(CC) $(CFLAGS) -I$(FW) -c $(TOP)/fw_m4/ca_fw_main.c -o $(B)/ca_fw_main.o
	$(CC) $(CFLAGS) -I$(FW) -nostartfiles --specs=nano.specs -u _printf_float -T $(TOP)/fw_m4/ca_m4.ld \
	  -Wl,--gc-sections -Wl,-Map=$(B)/ca_fw.map $(B)/ca_fw_main.o $(B)/test_ca_fw.o $(B)/test_bc_fw.o $(B)/kat_data.c \
	  $(FW)/startup_stm32f407.s $(FW)/system_init.c $(FW)/semihost.c $(OWN_OBJ) $(ASCON_OBJ) -o $@
	$(OBJCOPY) -O binary $@ $(B)/ca_fw.bin
	arm-none-eabi-size $@

fw: $(FW_ELF)

# A firmware that reads one byte past the guarded buffer on purpose: shows the MPU
# bounds gate fires on this board (m4_board.py --expect-guard-fault).
$(B)/ca_fw_selftest.elf: $(FW_ELF)
	$(CC) $(CFLAGS) -I$(FW) -DGUARD_SELFTEST -c $(TOP)/fw_m4/ca_fw_main.c -o $(B)/ca_fw_main_selftest.o
	$(CC) $(CFLAGS) -I$(FW) -nostartfiles --specs=nano.specs -u _printf_float -T $(TOP)/fw_m4/ca_m4.ld \
	  -Wl,--gc-sections $(B)/ca_fw_main_selftest.o $(B)/test_ca_fw.o $(B)/test_bc_fw.o $(B)/kat_data.c \
	  $(FW)/startup_stm32f407.s $(FW)/system_init.c $(FW)/semihost.c $(OWN_OBJ) $(ASCON_OBJ) -o $@
	$(OBJCOPY) -O binary $@ $(B)/ca_fw_selftest.bin

guard-selftest: $(B)/ca_fw_selftest.elf
	python3 $(TOP)/tools/m4_board.py --expect-guard-fault --elf $< --bin $(B)/ca_fw_selftest.bin \
	  --csv /dev/null --log-dir $(B)

board: $(FW_ELF)
	@mkdir -p $(TOP)/results/arm
	python3 $(TOP)/tools/m4_board.py --elf $(FW_ELF) --bin $(B)/ca_fw.bin \
	  --csv $(TOP)/results/arm/m4-board.csv --log-dir $(B)

clean:
	rm -rf $(B)

.PHONY: guard-selftest all test cycles clean board fw
