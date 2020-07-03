# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

SOURCES = $(wildcard src)
CLEAN = $(addsuffix _clean,$(SOURCES))

.PHONY: clean $(SOURCES) $(CLEAN)

all: $(SOURCES) prod-img
clean: $(CLEAN)
build: $(SOURCES)

system-img:
	$(MAKE) -C test/docker system

prod-img:
	$(MAKE) -C test/docker prod

init-submodules:
	git submodule update --init

init-dependencies:
	sudo apt install -y clang llvm gcc-multilib build-essential docker.io python3 python3-pip linux-headers-$(uname -r) libelf-dev zlib1g-dev

init: init-submodules init-dependencies system-img

$(SOURCES):
	$(MAKE) -C $@

$(CLEAN):
	$(MAKE) -C $(subst _clean,,$@) clean

help:
	@echo 'all		build + docker'
	@echo 'clean		remove build products from src folder'
	@echo 'build		build content of scr folder'
	@echo 'system-img	(re)build docker system image'
	@echo 'prod-img		(re)build docker production image'
	@echo 'init		submodule init + install dependencies + docker-system'
