USER_TARGETS := \
    cli_cfg \
    cli_tunnel \
    cli_service \
    cli_nat \
    cli_gc

USER_LIBS := -lz

COMMON_DIR = ../../common
HEADER_DIR = ../../headers
LIBBPF_DIR = ../../libbpf/src/

include $(COMMON_DIR)/common.mk

attach:
	./attach_tc.sh lo
	sudo ls -R /sys/fs/bpf/

detach:
	./detach_tc.sh lo
	sudo ls -R /sys/fs/bpf/
