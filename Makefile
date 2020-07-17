# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

SOURCES = $(wildcard src)
CLEAN = $(addsuffix _clean,$(SOURCES))

.PHONY: clean $(SOURCES) $(CLEAN) check test

all: build check prod-img

clean: $(CLEAN)

build: $(SOURCES)

rebuild: clean build

system-img:
	$(MAKE) -C test/docker system

prod-img:
	$(MAKE) -C test/docker prod

init-submodules:
	git submodule update --init

init-dependencies:
	sudo apt install -y clang llvm gcc-multilib build-essential docker.io python3 python3-pip linux-headers-$(uname -r) libelf-dev zlib1g-dev

init: init-submodules init-dependencies system-img

test:
	$(MAKE) -C test/basic

attach:
	$(MAKE) -C src attach

detach:
	$(MAKE) -C src detach

check:
	$(MAKE) -C src attach detach

$(SOURCES):
	$(MAKE) -C $@

$(CLEAN):
	$(MAKE) -C $(subst _clean,,$@) clean

help:
	@echo 'all              build + check + prod-img'
	@echo 'clean            remove build products from src folder'
	@echo 'build            build content of scr folder'
	@echo 'rebuild          clean + build'
	@echo 'check            try to attach/detach TCs locally'
	@echo 'system-img       (re)build docker system image'
	@echo 'prod-img         (re)build docker production image'
	@echo 'init             submodule init + install dependencies + system-img'
	@echo 'test             execute simple test scenario test/basic/test_01.sh'
