NAME=farcasterd
REPO=probely/$(NAME)
PLATFORMS=linux/arm64,linux/amd64
VER_MAJOR=$(shell echo ${VERSION} | awk -F'.' '{print $$1}')
VER_MINOR=$(shell echo ${VERSION} | awk -F'.' '{print $$2}')

COMMIT=$(shell git rev-parse --short HEAD)
COMPAT_IMAGE=${NAME}-linux-compat
LDFLAGS=-ldflags "-X probely.com/farcaster/settings.Version=${VERSION} -X probely.com/farcaster/settings.Commit=${COMMIT}"
GOFILES := $(shell find . -name '*.go')

.DEFAULT_GOAL: $(NAME)

$(NAME): ${GOFILES} check-env
	go build ${LDFLAGS} -o bin/${NAME}

fmt:
	go fmt ./...

vet: fmt
	go vet ./...

linux-compat: linux-compat-build linux-compat-extract

linux-compat-build:
	docker build --build-arg VERSION=$(VERSION) -t farcasterd-linux-compat -f Dockerfile.build .

linux-compat-extract: linux-compat-build
	@docker rm -f ${NAME}-tmp-container || true
	docker create --name ${NAME}-tmp-container ${COMPAT_IMAGE}
	for arch in amd64 arm64; do \
		docker cp ${NAME}-tmp-container:/build/bin/${NAME}-linux-$${arch} ./bin || true; \
	done
	docker rm ${NAME}-tmp-container

windows:
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o bin/${NAME}-windows-amd64.exe
	GOOS=windows GOARCH=arm64 go build ${LDFLAGS} -o bin/${NAME}-windows-arm64.exe

linux:
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o bin/${NAME}-linux-amd64
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o bin/${NAME}-linux-arm64

darwin:
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o bin/${NAME}-darwin-amd64
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o bin/${NAME}-darwin-arm64

lint:
	@command -v docker >/dev/null || { echo "You need Docker installed to run the linter" && exit 1; }
	docker run --rm -v $(shell pwd):/app -w /app golangci/golangci-lint golangci-lint run -v

docker: check-env
	docker buildx build --builder multiarch -f Dockerfile \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		-t $(REPO):v$(VER_MAJOR) -t $(REPO):v$(VER_MAJOR).$(VER_MINOR) -t $(REPO):v$(VERSION) \
		--push .

docker-clean:
	docker buildx rm multiarch || true

docker-prepare:
	docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
	docker buildx create --name multiarch --driver docker-container
	docker buildx inspect --builder multiarch --bootstrap

check-env:
ifndef VERSION
	$(error VERSION env variable is undefined. Set it with `VERSION=x.y.z make ...`)
endif
	@# VERSION must be a valid semver
	@echo ${VERSION} | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || (echo "VERSION must be a valid semver" && exit 1)

.PHONY: windows linux linux-compat linux-compat-build linux-compat-extract darwin lint
.PHONY: docker docker-clean docker-prepare
