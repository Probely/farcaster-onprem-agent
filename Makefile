CONTAINER := farcaster-onprem-agent
REPO := probely/$(CONTAINER)
PLATFORMS := linux/arm64,linux/amd64
LOCAL_PLATFORM := linux/$(shell uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
VERSION ?=
VER_MAJOR := $(shell echo '$(VERSION)' | cut -d. -f1)
VER_MINOR := $(shell echo '$(VERSION)' | cut -d. -f2)
BINFMT_IMAGE ?= tonistiigi/binfmt
BINFMT_CMD ?= docker run --rm --privileged $(BINFMT_IMAGE) --install all
GO_MODULES := farcaster-go farconn contrib/proxyprobe
SHELL_SCRIPTS := $(wildcard scripts/*.sh tests/shell/*.sh) \
	farconn/host-check.sh contrib/proxyprobe/test-connectivity.sh \
	tests/proxy/runner/proxy-enforcer.sh

TAGS := -t $(REPO):v$(VER_MAJOR) \
	-t $(REPO):v$(VER_MAJOR).$(VER_MINOR) \
	-t $(REPO):v$(VERSION)

MODERN_TAGS := -t $(REPO):v$(VER_MAJOR)-modern \
	-t $(REPO):v$(VER_MAJOR).$(VER_MINOR)-modern \
	-t $(REPO):v$(VERSION)-modern

BUILDX_ARGS := --builder multiarch \
	--build-arg "VERSION=$(VERSION)"


MODERN_BUILDX_ARGS = \
	--build-arg RUST_BUILDER_BASE=rust:1-trixie \
	--build-arg GO_BUILDER_BASE=golang:1.26-trixie \
	--build-arg FINAL_BASE=debian:13.6-slim \
	--build-arg GCC_VERSION=14

.PHONY: all build build-local build-modern build-local-modern clean prepare check-version
.PHONY: check check-go check-shell lint test-proxy test-agent

all: build

check: check-shell check-go

check-go:
	@set -e; for module in $(GO_MODULES); do \
		echo "Checking $$module"; \
		(cd "$$module" && go vet ./... && env -u FARCASTER_AGENT_TOKEN go test ./...); \
	done

check-shell:
	@command -v shellcheck >/dev/null || { echo "ShellCheck is required. Install it with your package manager and rerun make check-shell." >&2; exit 1; }
	@for script in $(SHELL_SCRIPTS); do bash -n "$$script" || exit 1; done
	shellcheck -x -P SCRIPTDIR $(SHELL_SCRIPTS)
	bash tests/shell/check.sh

lint:
	cd farcaster-go && golangci-lint run --new-from-rev=origin/main

test-proxy:
	@trap 'docker compose -f tests/proxy/docker-compose.yml down' EXIT; \
		docker compose -f tests/proxy/docker-compose.yml up --build --abort-on-container-exit --exit-code-from testrunner

test-agent:
	@test -n "$$FARCASTER_AGENT_TOKEN" || { echo "Set FARCASTER_AGENT_TOKEN to a test agent token before running make test-agent." >&2; exit 1; }
	@trap 'docker compose -f tests/agent/docker-compose.yml down' EXIT; \
		docker compose -f tests/agent/docker-compose.yml up --build

build: check-version prepare
	docker buildx build $(BUILDX_ARGS) \
		--platform $(PLATFORMS) \
		$(TAGS) \
		--push .

build-local: check-version prepare
	docker buildx build $(BUILDX_ARGS) \
		--platform $(LOCAL_PLATFORM) \
		-t $(REPO):v$(VERSION) \
		--load .

build-modern: check-version prepare
	docker buildx build $(BUILDX_ARGS) $(MODERN_BUILDX_ARGS) \
		--platform $(PLATFORMS) \
		$(MODERN_TAGS) \
		--push .

build-local-modern: check-version prepare
	docker buildx build $(BUILDX_ARGS) $(MODERN_BUILDX_ARGS) \
		--platform $(LOCAL_PLATFORM) \
		-t $(REPO):v$(VERSION)-modern \
		--load .

clean:
	docker buildx --builder multiarch prune -f

prepare: check-version
	$(BINFMT_CMD)
	@if ! docker buildx inspect multiarch >/dev/null 2>&1; then \
		docker buildx create --name multiarch --driver docker-container --use --platform $(PLATFORMS); \
	else \
		docker buildx use multiarch; \
	fi
	docker buildx inspect --builder multiarch --bootstrap

check-version:
	@if ! echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "ERROR: VERSION must be x.y.z. Run make VERSION=0.0.0 build-local for a local build."; \
		exit 1; \
	fi
