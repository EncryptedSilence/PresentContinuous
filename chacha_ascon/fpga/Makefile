# Full-round FPGA cores: RTL simulation against the KAT-verified host references.
#
#   make sim       host KAT suite, vectors, then every core under iverilog (PASS/FAIL per core)
#   make vectors   only regenerate the vectors in build/ca/fpga/vec
#   make oss       open-source estimate on the GW5A-25A (yosys + nextpnr-himbaechel, no license)
#                  -> ../results/fpga/oss-gw5a.csv
#   make gowin-projects   Gowin IDE projects in gen/ (building them needs a license, see README.md)
#   make gowin-build gowin-sweep gowin-report   batch build with gw_sh, clock-constraint sweep,
#                  then collect the reports
CC       ?= gcc
IVERILOG ?= iverilog
VVP      ?= vvp
B        := ../../build/ca
X        := $(B)/x86
FB       := $(B)/fpga
R        := ../..
VEC      := $(FB)/vec

HOST_OBJ := $(X)/aes/aes128_ref.o $(X)/qalqan/qalqan.o $(X)/qalqan/qalqan_ctr.o $(X)/chacha/chacha20_ref.o \
            $(X)/ascon-c/ref.o
PRESENT_OBJ := $(addprefix $(R)/build/src/,variant.o keyschedule.o present_core.o present_ref.o present_table.o \
               present_table_x.o present_bitslice.o present_bitslice32.o present_avx2.o present_neon.o gen/variants_gen.o)

RTL_TABLES := rtl/aes_sbox.vh rtl/qalqan_sbox.vh
CTR_CORES  := AES128:aes128:rtl/aes_ctr.v AES256:aes256:rtl/aes_ctr.v \
              $(if $(wildcard rtl/qalqan_ctr.v),QALQAN:qalqan:rtl/qalqan_ctr.v) \
              CHACHA:chacha20:rtl/chacha20_ctr.v PRESENT:present80:rtl/present80_ctr.v
# rtl/qalqan_ctr.v (the Qalqan core) is not distributed; without it the Qalqan sim is skipped.

.NOTPARALLEL:
all: sim

host-verified:
	$(MAKE) -C .. test
	$(MAKE) -C $(R) $(patsubst $(R)/%,%,$(PRESENT_OBJ))
$(HOST_OBJ) $(PRESENT_OBJ): host-verified ;

$(RTL_TABLES): tools/gen_tables.py ../src/aes/aes128_ref.c ../src/qalqan/qalqan.c
	python3 tools/gen_tables.py rtl

$(FB)/gen_vectors: tools/gen_vectors.c $(HOST_OBJ) $(PRESENT_OBJ)
	@mkdir -p $(FB)
	$(CC) -O2 -std=gnu11 -Wall -Wextra -I../include -I../src/qalqan -I$(R)/include $< $(HOST_OBJ) $(PRESENT_OBJ) -o $@

vectors: $(FB)/gen_vectors
	@mkdir -p $(VEC)
	$(FB)/gen_vectors $(VEC)

sim: $(RTL_TABLES) vectors
	@set -e; for spec in $(CTR_CORES); do \
	  def=$${spec%%:*}; rest=$${spec#*:}; vec=$${rest%%:*}; src=$${rest#*:}; \
	  $(IVERILOG) -g2012 -Wall -Irtl -DCORE_$$def -o $(FB)/tb_$$vec.vvp tb/tb_ctr.v $$src; \
	  $(VVP) -n $(FB)/tb_$$vec.vvp +vec=$(VEC)/$$vec.vec | tee $(FB)/sim_$$vec.log | grep -E "PASS|FAIL|MISMATCH|got|exp"; \
	  grep -q "^PASS" $(FB)/sim_$$vec.log; \
	done
	$(IVERILOG) -g2012 -Wall -Irtl -o $(FB)/tb_ascon.vvp tb/tb_ascon.v rtl/ascon128_aead.v
	$(VVP) -n $(FB)/tb_ascon.vvp +vec=$(VEC)/ascon128.vec | tee $(FB)/sim_ascon.log | grep -E "PASS|FAIL|MISMATCH|got|exp"
	@grep -q "^PASS" $(FB)/sim_ascon.log

sim-%: $(RTL_TABLES) vectors
	@spec=$$(echo "$(CTR_CORES)" | tr ' ' '\n' | grep ":$*:"); def=$${spec%%:*}; rest=$${spec#*:}; src=$${rest#*:}; \
	  $(IVERILOG) -g2012 -Wall -Irtl -DCORE_$$def -o $(FB)/tb_$*.vvp tb/tb_ctr.v $$src && \
	  $(VVP) -n $(FB)/tb_$*.vvp +vec=$(VEC)/$*.vec

oss: $(RTL_TABLES)
	python3 tools/oss_flow.py

gowin-projects: $(RTL_TABLES)
	python3 tools/gen_gowin.py

gowin-build: gowin-projects
	cd $(R) && GEN_DIR=$(CURDIR)/gen fpga/build_all_gowin.sh

gowin-sweep:
	cd $(R) && python3 chacha_ascon/fpga/tools/gowin_sweep.py

gowin-report:
	cd $(R) && python3 tools/gowin_collect.py --gen-dir chacha_ascon/fpga/gen \
	  --csv chacha_ascon/results/fpga/gowin-gw5a.csv --md chacha_ascon/results/fpga/gowin-gw5a.md

.PHONY: all sim vectors host-verified oss gowin-projects gowin-build gowin-sweep gowin-report
