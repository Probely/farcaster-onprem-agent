CONTAINER := farcaster-onprem-agent
REPO := probely/$(CONTAINER)
PLATFORMS := linux/arm64,linux/amd64

VERSION ?= $(error VERSION is undefined. Usage: VERSION=x.y.z make [target])
VER_MAJOR := $(shell echo '$(VERSION)' | cut -d. -f1)
VER_MINOR := $(shell echo '$(VERSION)' | cut -d. -f2)

TAGS := -t $(REPO):v$(VER_MAJOR) \
	-t $(REPO):v$(VER_MAJOR).$(VER_MINOR) \
	-t $(REPO):v$(VERSION)

BUILDX_ARGS := --builder multiarch \
	--build-arg "VERSION=$(VERSION)"

.PHONY: all build build-local clean prepare check-version

all: build

build: check-version prepare
	docker buildx build $(BUILDX_ARGS) \
		--platform $(PLATFORMS) \
		$(TAGS) \
		--push .

build-local: check-version prepare
	docker buildx build $(BUILDX_ARGS) \
		--platform linux/amd64 \
		-t $(REPO):v$(VERSION) \
		--load .

clean:
	docker buildx --builder multiarch prune -f

prepare:
	docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
	docker buildx create --name multiarch --driver docker-container --use || true
	docker buildx inspect --builder multiarch --bootstrap

check-version:
	@if ! echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "ERROR: VERSION must be a valid semver (x.y.z)"; \
		exit 1; \
	fi