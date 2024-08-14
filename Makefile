CONTAINER=farcaster-onprem-agent
REPO=probely/$(CONTAINER)
PLATFORMS=linux/arm64,linux/amd64
VER_MAJOR=$(shell echo ${VERSION} | awk -F'.' '{print $$1}')
VER_MINOR=$(shell echo ${VERSION} | awk -F'.' '{print $$2}')

.PHONY: build build-local clean prepare check-env

build: check-env
	docker buildx build --builder multiarch \
		--platform $(PLATFORMS) \
		--build-arg "VERSION=${VERSION}" \
		-t $(REPO):v$(VER_MAJOR) -t $(REPO):v$(VER_MAJOR).$(VER_MINOR) -t $(REPO):v$(VERSION) \
		--push .

build-local: check-env
	$(eval PLATFORMS=linux/amd64)
	docker buildx build --builder multiarch \
		--platform $(PLATFORMS) \
		--build-arg "VERSION=${VERSION}" \
		-t $(REPO):v$(VERSION) \
		--load \
		.

clean:
	docker buildx --builder multiarch prune
prepare:
	docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
	docker buildx create --name multiarch --driver docker-container
	docker buildx inspect --builder multiarch --bootstrap

check-env:
ifndef VERSION
	$(error VERSION env variable is undefined. Set it with `VERSION=x.y.z make ...`)
endif
	@# VERSION must be a valid semver
	@echo ${VERSION} | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || (echo "VERSION must be a valid semver" && exit 1)
