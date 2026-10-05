# Makefile for the seccomp policy compiler + minimal probe.
#
# Default build is for the build host and is used to run the tool's own test
# suite.  For the actual Linux x86-64 deliverable use the x86_64 target,
# which requires an x86-64 C cross compiler:
#
#   make x86_64 CC_X86=x86_64-linux-gnu-gcc
#
# Targets:
#   make            build native probe + all policy artifacts + run tests
#   make x86_64     build probe for x86-64 and compile the x86-64 filters
#   make test       differential (evaluator vs cBPF interpreter) + kernel
#   make clean

PY      ?= python3
CC       = gcc
CC_X86  ?= x86_64-linux-gnu-gcc

OUT     := out
TOOLS   := tools
POL     := policies

FILTERS := $(OUT)/probe_x86_64.filter $(OUT)/probe_aarch64.filter \
           $(OUT)/longjump_x86_64.filter $(OUT)/longjump_aarch64.filter

.PHONY: all filters x86_64 test difftest kernel clean

all: filters $(OUT)/probe test

filters: $(FILTERS)

$(OUT):
	mkdir -p $(OUT)

# --- policy compilation -----------------------------------------------------
$(OUT)/probe_x86_64.filter: $(POL)/probe.json | $(OUT)
	$(PY) $(TOOLS)/seccompcc $< -o $(OUT)/probe_x86_64

$(POL)/probe_aarch64.json: $(POL)/probe.json $(TOOLS)/mk_aarch64.py
	$(PY) $(TOOLS)/mk_aarch64.py $< $@

$(OUT)/probe_aarch64.filter: $(POL)/probe_aarch64.json | $(OUT)
	$(PY) $(TOOLS)/seccompcc $< -o $(OUT)/probe_aarch64

$(OUT)/longjump_x86_64.filter: $(POL)/longjump.json | $(OUT)
	$(PY) $(TOOLS)/seccompcc $< -o $(OUT)/longjump_x86_64

$(POL)/longjump_aarch64.json: $(POL)/longjump.json $(TOOLS)/mk_aarch64.py
	$(PY) $(TOOLS)/mk_aarch64.py $< $@

$(OUT)/longjump_aarch64.filter: $(POL)/longjump_aarch64.json | $(OUT)
	$(PY) $(TOOLS)/seccompcc $< -o $(OUT)/longjump_aarch64

# --- probe binaries ---------------------------------------------------------
$(OUT)/probe: probe/probe.c | $(OUT)
	$(CC) -O2 -Wall -Wextra -o $@ probe/probe.c

x86_64: $(OUT)/probe-x86_64 $(OUT)/probe_x86_64.filter $(OUT)/longjump_x86_64.filter
	@echo "x86-64 artifacts: $(OUT)/probe-x86_64, $(OUT)/probe_x86_64.filter"

$(OUT)/probe-x86_64: probe/probe.c | $(OUT)
	$(CC_X86) -O2 -Wall -Wextra -static -o $@ probe/probe.c

# --- tests ------------------------------------------------------------------
difftest:
	$(PY) $(TOOLS)/difftest.py

# kernel stage uses the native binary + native-arch filter, and loads the
# opposite-arch filter only to prove the arch gate fires in the real kernel.
kernel: $(OUT)/probe $(OUT)/probe_aarch64.filter $(OUT)/probe_x86_64.filter \
        $(OUT)/longjump_aarch64.filter $(OUT)/longjump_x86_64.filter
	@uname_m=$$(uname -m); \
	if [ "$$uname_m" = "x86_64" ]; then \
	  $(PY) $(TOOLS)/check_kernel.py $(OUT)/probe $(OUT)/probe_x86_64.filter \
	    x86_64 --foreign $(OUT)/probe_aarch64.filter \
	    --longjump $(OUT)/longjump_x86_64.filter; \
	else \
	  $(PY) $(TOOLS)/check_kernel.py $(OUT)/probe $(OUT)/probe_aarch64.filter \
	    aarch64 --foreign $(OUT)/probe_x86_64.filter \
	    --longjump $(OUT)/longjump_aarch64.filter; \
	fi

test: filters $(OUT)/probe difftest kernel

clean:
	rm -rf $(OUT) $(POL)/probe_aarch64.json $(POL)/longjump_aarch64.json
