USER_TARGETS := \
    cli_cfg \
    cli_tunnel \
    cli_service

USER_LIBS := -lz -lssl -lcrypto

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
