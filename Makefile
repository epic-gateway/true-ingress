SOURCES = libbpf/src headers common src/cli src/bpf
CLEAN = $(addsuffix _clean,$(SOURCES))
TARFILE = pkg/true-ingress.tar.bz2
# These will be set if we're building in a gitlab CI environment and
# we'll default it to "dev" in other cases
CI_COMMIT_REF_NAME ?= dev
CI_COMMIT_SHORT_SHA ?= dev

.PHONY: clean $(SOURCES) $(CLEAN) clean-tar check test prod-img

all: tar

clean: $(CLEAN) clean-tar

build: $(SOURCES) go

rebuild: clean build

docker:
	test/docker/prod.sh ${TAG}

push: docker
	docker push ${TAG}

test: docker
	$(MAKE) -C test/ebpf

attach:
	$(MAKE) -C src attach

detach:
	$(MAKE) -C src detach

check:
	$(MAKE) -C src attach detach

go:
	CGO_ENABLED=0 go build -ldflags "-X main.version=${CI_COMMIT_REF_NAME} -X main.commit=${CI_COMMIT_SHORT_SHA}" -tags 'osusergo netgo' ./cmd/gue_ping_svc_auto
	CGO_ENABLED=0 go build -ldflags "-X main.version=${CI_COMMIT_REF_NAME} -X main.commit=${CI_COMMIT_SHORT_SHA}" -tags 'osusergo netgo' ./cmd/pfc_cli_go

tar: build
	mkdir -p pkg/bin

	echo $(CI_COMMIT_REF_NAME) / $(CI_COMMIT_SHORT_SHA) > pkg/bin/VERSION

	# Copy eBPF
	cp ./src/bpf/*.o pkg/bin/

	# Copy CLI
	cp ./src/cli/cli_cfg ./src/cli/cli_service ./src/cli/cli_tunnel pkg/bin/

	# for GUE Ping
	cp ./gue_ping_svc_auto ./pfc_cli_go pkg/bin/

	chmod +x pkg/bin/*

	tar cfj $(TARFILE) --directory=pkg bin

$(SOURCES):
	$(MAKE) -C $@

clean-tar:
	rm -rf pkg

$(CLEAN):
	rm -rf pfc_cli_go gue_ping_svc_auto
	$(MAKE) -C $(subst _clean,,$@) clean

help:
	@echo 'all              build + check + prod-img'
	@echo 'clean            remove build products from src folder'
	@echo 'build            build content of scr folder'
	@echo 'rebuild          clean + build'
	@echo 'check            try to attach/detach TCs locally'
	@echo 'docker           (re)build docker image (set TAG to override default tag)'
	@echo 'push             push docker image (set TAG to override default tag)'
	@echo 'test             execute simple test scenario test/ebpf/test_go.sh'
	@echo "tar              create $(TARFILE) containing all required binaries and scripts"
