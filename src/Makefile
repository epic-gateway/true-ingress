# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

BPF_TARGETS := \
    pfc_ingress_tc \
    pfc_egress_tc \
    egw_ingress_tc \
    egw_egress_tc

USER_TARGETS := \
    cli_cfg

USER_LIBS := -lz
#COPY_LOADER = xdp_loader

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src
COMMON_DIR = ../common

include $(COMMON_DIR)/common.mk
