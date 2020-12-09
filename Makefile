SOURCES = libbpf/src headers common src test/docker src/go
CLEAN = $(addsuffix _clean,$(SOURCES))
TARFILE = pfc.tar.bz2

.PHONY: clean $(SOURCES) $(CLEAN) clean-tar check test prod-img

all: build check

clean: $(CLEAN) clean-tar

build: $(SOURCES)

rebuild: clean build

docker:
	test/docker/prod.sh ${TAG}

push: docker
	docker push ${TAG}

init-submodules:
	git submodule update --init

init-dependencies:
	scripts/dependencies.sh
	scripts/docker.sh

init: init-submodules init-dependencies

test: docker
	$(MAKE) -C test/ebpf

attach:
	$(MAKE) -C src attach

detach:
	$(MAKE) -C src detach

check:
	$(MAKE) -C src attach detach

go:
	$(MAKE) -C test/docker go
	$(MAKE) -C src/go go

tar: build
	mkdir -p pkg/bin

	# Copy eBPF
	cp ./src/*.o pkg/bin/

	# Copy CLI
	cp ./src/cli_cfg ./src/cli_service ./src/cli_tunnel ./src/cli_gc pkg/bin/

	# for GUE Ping
	cp ./test/docker/gue_ping_svc_auto ./src/go/pfc_cli_go pkg/bin/

	chmod +x pkg/bin/*

	tar cfj $(TARFILE) --directory=pkg bin

$(SOURCES):
	$(MAKE) -C $@

clean-tar:
	rm -f $(TARFILE)

$(CLEAN):
	$(MAKE) -C $(subst _clean,,$@) clean

help:
	@echo 'all              build + check + prod-img'
	@echo 'clean            remove build products from src folder'
	@echo 'build            build content of scr folder'
	@echo 'rebuild          clean + build'
	@echo 'check            try to attach/detach TCs locally'
	@echo 'docker           (re)build docker image (set TAG to override default tag)'
	@echo 'push             push docker image (set TAG to override default tag)'
	@echo 'init             submodule init + install dependencies'
	@echo 'test             execute simple test scenario test/ebpf/test_go.sh'
	@echo "tar              create $(TARFILE) containing all required binaries and scripts"
