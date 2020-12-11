# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  BPF_TARGETS and USER_TARGETS
# as a space-separated list
#
LLC ?= llc
CLANG ?= clang
CC ?= gcc

BPF_C = ${BPF_TARGETS:=.c}
BPF_OBJ = ${BPF_C:.c=.o}
USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}

# Expect this is defined by including Makefile, but define if not
COMMON_DIR ?= ../common/
LIBBPF_DIR ?= ../libbpf/src/
HEADER_DIR ?= ../headers/

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

# Extend if including Makefile already added some
#COMMON_OBJS += $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o
COMMON_OBJS += $(COMMON_DIR)/cli_util.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

CFLAGS ?= -g
CFLAGS += -I$(HEADER_DIR) -I $(COMMON_DIR)
LDFLAGS ?= -L$(LIBBPF_DIR)

BPF_CFLAGS ?= -g -I../libbpf/include/uapi -I$(HEADER_DIR)

LIBS = -l:libbpf.a -lelf $(USER_LIBS)

all: llvm-check $(USER_TARGETS) $(BPF_OBJ)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -f $(USER_TARGETS) $(BPF_OBJ) $(USER_OBJ)
	rm -f $(BPF_OBJ)
	rm -f *.ll
	rm -f *~

# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

# Create dependency: detect if C-file change and touch H-file, to trigger
# target $(COMMON_OBJS)
$(COMMON_H): %.h: %.c
	touch $@

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS): %.o: %.h
	make -C $(COMMON_DIR)

$(USER_TARGETS): %: %.c  $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_OBJS) \
	 $< $(LIBS)

$(BPF_OBJ): %.o: %.c $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
