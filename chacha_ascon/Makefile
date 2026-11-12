# ChaCha20 / Ascon-AEAD128 speed study -- host (x86-64) build.
#   make -C chacha_ascon            test + bench binaries under build/ca/x86
#   make -C chacha_ascon test       run every KAT on every available implementation
#                                   (test_ca: ChaCha20/Ascon; test_bc: AES-128-CTR/Qalqan-CTR)
# ARM (Cortex-A7, Cortex-M4) builds: arm/Makefile.  CUDA: cuda/Makefile.
#
# ascon-c implementations are compiled unmodified from third_party/ext/ascon-c
# (tools/fetch_ext.sh pins the commit). Each one defines the same eBACS symbols, so
# each is linked into a relocatable object and every global but its two entry
# points is localised, which are then renamed ascon_c_<impl>_{en,de}crypt.

CC      ?= cc
OPT     ?= -O3 -march=native
CFLAGS  += $(OPT) -std=gnu11 -Wall -Wextra -Wno-format-truncation -Iinclude -Itests -Isrc/qalqan -Isrc/aes
B       := ../build/ca/x86
EXT     := ../third_party/ext
ASCONC  := $(EXT)/ascon-c/crypto_aead/asconaead128
ASCON_C_IMPLS := ref opt64 opt64_lowsize opt32 bi32

OWN_SRC := src/chacha/chacha20_ref.c src/chacha/chacha20_avx2.c \
           src/ascon/ascon_common.c src/ascon/ascon_avx2.c src/ascon/ascon_scalar_multi.c src/registry_x86.c \
           src/aes/aes128_ref.c src/aes/aes128_ttable.c src/aes/aes128_ni.c src/aes/aes128_bs.c \
           src/qalqan/qalqan.c src/qalqan/qalqan_ctr.c
# Accelerated Qalqan kernels (GFNI, T-table x8, bitslice AVX2) are not distributed
# (.gitignore); when present they are built and registered, otherwise only the reference.
QALQAN_FAST := $(wildcard src/qalqan/qalqan_x86.c src/qalqan/qalqan_bs.c)
ifeq ($(words $(QALQAN_FAST)),2)
OWN_SRC += $(QALQAN_FAST)
CFLAGS  += -DHAVE_QALQAN_X86
endif
OWN_OBJ := $(patsubst src/%.c,$(B)/%.o,$(OWN_SRC))
ASCON_OBJ := $(patsubst %,$(B)/ascon-c/%.o,$(ASCON_C_IMPLS))

all: $(B)/test_ca $(B)/test_bc $(B)/bench_ca

$(B)/%.o: src/%.c include/*.h src/*.h src/qalqan/*.h src/aes/*.h src/aes/aes128_bs_sbox.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# The bitslice kernels (Qalqan, AES) must not use GFNI/AES instructions, even ones the compiler
# would pick by itself (GCC lowers some byte shifts/rotates to GF2P8AFFINEQB under -mgfni).
# Register-pressure-aware pre-RA scheduling: ~10-15% on these long AND/XOR circuits.
$(B)/qalqan/qalqan_bs.o $(B)/aes/aes128_bs.o: CFLAGS += -mno-gfni -mno-aes -mno-vaes -mno-vpclmulqdq -mno-pclmul \
                                   -fschedule-insns -fsched-pressure

# The S-box circuit generator is distributed only with the accelerated Qalqan kernels;
# without it the committed src/aes/aes128_bs_sbox.h is used as is.
ifneq ($(wildcard tools/gen_qalqan_bs_sbox.py),)
src/qalqan/qalqan_bs_sbox.h src/aes/aes128_bs_sbox.h &: tools/gen_qalqan_bs_sbox.py
	python3 $< src/qalqan/qalqan_bs_sbox.h src/aes/aes128_bs_sbox.h
$(B)/qalqan/qalqan_bs.o: src/qalqan/qalqan_bs_sbox.h
endif

# one relocatable object per ascon-c implementation, entry points renamed
$(B)/ascon-c/%.o: $(ASCONC)/%/*.c $(ASCONC)/%/*.h
	@mkdir -p $(B)/ascon-c/$*
	cd $(B)/ascon-c/$* && for f in $(abspath $(ASCONC))/$*/*.c; do \
	  $(CC) $(OPT) -std=gnu11 -I$(abspath $(ASCONC))/$* -I$(abspath $(EXT))/ascon-c/tests \
	    -c $$f -o $$(basename $$f .c).o || exit 1; done
	ld -r -o $@.tmp $(B)/ascon-c/$*/*.o
	objcopy --keep-global-symbol=crypto_aead_encrypt --keep-global-symbol=crypto_aead_decrypt $@.tmp $@.tmp2
	objcopy --redefine-sym crypto_aead_encrypt=ascon_c_$(subst -,_,$*)_encrypt \
	  --redefine-sym crypto_aead_decrypt=ascon_c_$(subst -,_,$*)_decrypt $@.tmp2 $@
	rm -f $@.tmp $@.tmp2

$(B)/kat_data.c: kat/*.txt tools/embed_kats.py
	@mkdir -p $(B)
	python3 tools/embed_kats.py $@

$(B)/test_ca: tests/test_ca.c tests/kat_common.h $(B)/kat_data.c $(OWN_OBJ) $(ASCON_OBJ)
	$(CC) $(CFLAGS) $< $(B)/kat_data.c $(OWN_OBJ) $(ASCON_OBJ) -o $@

$(B)/test_bc: tests/test_bc.c tests/kat_common.h $(OWN_OBJ) $(ASCON_OBJ)
	$(CC) $(CFLAGS) $< $(OWN_OBJ) $(ASCON_OBJ) -o $@

$(B)/bench_ca: bench/bench_ca.c $(OWN_OBJ) $(ASCON_OBJ)
	$(CC) $(CFLAGS) $< $(OWN_OBJ) $(ASCON_OBJ) -lm -lpthread -o $@

test: $(B)/test_ca $(B)/test_bc
	$(B)/test_ca
	$(B)/test_bc

# The same tests with every object (ascon-c included) built under AddressSanitizer:
# the test allocates every input and output at its exact size, so any read or write
# past a tail is reported.
asan-test:
	$(MAKE) B=../build/ca/x86-asan OPT="-O1 -g -march=native -fsanitize=address -fno-omit-frame-pointer" ../build/ca/x86-asan/test_ca ../build/ca/x86-asan/test_bc
	../build/ca/x86-asan/test_ca
	../build/ca/x86-asan/test_bc

clean:
	rm -rf $(B)

.PHONY: all test asan-test clean
