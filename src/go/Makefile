# These will be set if we're building in a gitlab CI environment and
# we'll default it to "dev" in other cases
CI_COMMIT_REF_NAME ?= dev
CI_COMMIT_SHORT_SHA ?= dev

all: go

clean:
	rm -rf pfc_cli_go gue_ping_svc_auto

go:
	go build -ldflags "-X main.version=${CI_COMMIT_REF_NAME} -X main.commit=${CI_COMMIT_SHORT_SHA}" -tags 'osusergo netgo' gue_ping_svc_auto.go
	go build -ldflags "-X main.version=${CI_COMMIT_REF_NAME} -X main.commit=${CI_COMMIT_SHORT_SHA}" -tags 'osusergo netgo' pfc_cli_go.go
