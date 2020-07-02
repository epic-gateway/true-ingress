# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

SOURCES = $(wildcard src/)
CLEAN = $(addsuffix _clean,$(SOURCES))

.PHONY: clean $(SOURCES) $(CLEAN)

all: $(SOURCES) docker
clean: $(CLEAN)
build: $(SOURCES)
docker:
	$(MAKE) -C test/docker

init:
	git submodule update --init
	sudo apt install -y clang llvm gcc-multilib build-essential docker.io python3 python3-pip linux-headers-$(uname -r) libelf-dev zlib1g-dev

$(SOURCES):
	$(MAKE) -C $@

$(CLEAN):
	$(MAKE) -C $(subst _clean,,$@) clean
