SOURCES = $(wildcard src)
CLEAN = $(addsuffix _clean,$(SOURCES))

.PHONY: clean $(SOURCES) $(CLEAN) check test prod-img

all: build check prod-img

clean: $(CLEAN)

build: $(SOURCES)

rebuild: clean build

prod-img:
	test/docker/prod.sh ${TAG}

push: prod-img
	docker push ${TAG}

init-submodules:
	git submodule update --init

init-dependencies:
	scripts/dependencies.sh

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
	@echo 'prod-img         (re)build docker production image (set TAG to override default tag)'
	@echo 'push             push docker image (set TAG to override default tag)'
	@echo 'init             submodule init + install dependencies + system-img'
	@echo 'test             execute simple test scenario test/basic/test_01.sh'
