.PHONY: all build run clean fmt vet lint test docker docker-local docker-push docker-clean docker-prepare check-env linux darwin

NAME := proxyprobe
REPO := probely/$(NAME)
PLATFORMS := linux/arm64,linux/amd64
BIN_DIR := bin

VERSION ?= $(error VERSION not set)
VERSION_PARTS := $(subst ., ,$(VERSION))
VER_MAJOR := $(word 1,$(VERSION_PARTS))
VER_MINOR := $(word 2,$(VERSION_PARTS))
DOCKER_TAGS := -t $(REPO):v$(VER_MAJOR) -t $(REPO):v$(VER_MAJOR).$(VER_MINOR) -t $(REPO):v$(VERSION)
LDFLAGS := -ldflags "-X main.Version=v${VERSION}"

GOFILES := $(shell find . -name '*.go')

BUILDS := \
	$(BIN_DIR)/$(NAME)-linux-amd64 \
	$(BIN_DIR)/$(NAME)-linux-arm64 \
	$(BIN_DIR)/$(NAME)-darwin-amd64 \
	$(BIN_DIR)/$(NAME)-darwin-arm64

.DEFAULT_GOAL := all

all: check-env fmt vet lint test build

build: $(BIN_DIR)/$(NAME)

$(BIN_DIR)/$(NAME): ${GOFILES}
	@mkdir -p $(BIN_DIR)
	go build ${LDFLAGS} -o $@

test:
	go test -v ./...

fmt:
	go fmt ./...

vet: fmt
	go vet ./...

lint:
	@command -v docker >/dev/null || { echo "ERROR: Docker is required for linting" >&2; exit 1; }
	docker run --rm -v $(CURDIR):/app -w /app golangci/golangci-lint golangci-lint run -v

$(BIN_DIR)/$(NAME)-%: ${GOFILES}
	@mkdir -p $(BIN_DIR)
	GOOS=$(word 1,$(subst -, ,$*)) GOARCH=$(word 2,$(subst -, ,$*)) go build ${LDFLAGS} -o $@

linux: check-env $(filter $(BIN_DIR)/$(NAME)-linux-%,$(BUILDS))

darwin: check-env $(filter $(BIN_DIR)/$(NAME)-darwin-%,$(BUILDS))

docker-local: check-env
	docker build -f Dockerfile \
		--build-arg VERSION=$(VERSION) \
		$(DOCKER_TAGS) .

docker-push: check-env
	docker buildx build --builder multiarch -f Dockerfile \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		$(DOCKER_TAGS) \
		--push .

docker-clean:
	docker buildx rm multiarch || true

docker-prepare:
	docker buildx rm multiarch 2>/dev/null || true
	docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
	docker buildx create --name multiarch --driver docker-container
	docker buildx inspect --builder multiarch --bootstrap

check-env:
ifndef VERSION
	$(error VERSION env variable is undefined. Set it with 'VERSION=x.y.z make ...')
endif
	@echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || \
		(echo "ERROR: VERSION must be a valid semver (x.y.z)" >&2 && exit 1)

clean:
	rm -rf $(BIN_DIR)
