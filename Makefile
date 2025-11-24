CONTAINER := farcaster-onprem-agent
REPO := probely/$(CONTAINER)
PLATFORMS := linux/arm64,linux/amd64
LOCAL_PLATFORM := linux/$(shell uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
VERSION ?= $(error VERSION is undefined. Usage: VERSION=x.y.z make [target])
VER_MAJOR := $(shell echo '$(VERSION)' | cut -d. -f1)
VER_MINOR := $(shell echo '$(VERSION)' | cut -d. -f2)
BINFMT_IMAGE ?= tonistiigi/binfmt
BINFMT_CMD ?= docker run --rm --privileged $(BINFMT_IMAGE) --install all

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
	--build-arg GO_BUILDER_BASE=golang:1.24-trixie \
	--build-arg FINAL_BASE=ubuntu:25.04 \
	--build-arg GCC_VERSION=14

.PHONY: all build build-local build-modern build-local-modern clean prepare check-version

all: build

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

prepare:
	$(BINFMT_CMD)
	@if ! docker buildx inspect multiarch >/dev/null 2>&1; then \
		docker buildx create --name multiarch --driver docker-container --use --platform $(PLATFORMS); \
	else \
		docker buildx use multiarch; \
	fi
	docker buildx inspect --builder multiarch --bootstrap

check-version:
	@if ! echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "ERROR: VERSION must be a valid semver (x.y.z)"; \
		exit 1; \
	fi
