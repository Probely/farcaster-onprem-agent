CONTAINER=farcaster-onprem-agent
TAG=${IMAGE_TAG}

.PHONY: all docker push clean ssh_configs

docker: check-env
	docker build -f docker/Dockerfile -t $(CONTAINER):$(TAG) .
	docker tag $(CONTAINER):$(TAG) probely/$(CONTAINER):$(TAG)

push: docker
	docker push probely/$(CONTAINER):$(TAG)

clean:
	docker rm -f $(CONTAINER) 2>/dev/null || true

check-env:
ifndef IMAGE_TAG
	$(error IMAGE_TAG env variable is undefined)
endif
