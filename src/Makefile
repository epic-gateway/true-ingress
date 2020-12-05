# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

BPF_TARGETS := \
    pfc_ingress_tc \
    pfc_egress_tc \
    pfc_tag_rx_tc \
    pfc_tag_tx_tc

USER_TARGETS := \
    cli_cfg \
    cli_tunnel \
    cli_service \
    cli_nat \
    cli_gc

USER_LIBS := -lz
#COPY_LOADER = xdp_loader

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src
COMMON_DIR = ../common

include $(COMMON_DIR)/common.mk

attach:
	./attach_tc.sh lo
	sudo ls -R /sys/fs/bpf/

detach:
	./detach_tc.sh lo
	sudo ls -R /sys/fs/bpf/
