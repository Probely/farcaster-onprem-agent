CONTAINER=farcaster-onprem-agent
TAG=latest

.PHONY: all docker push clean ssh_configs

docker:
	docker build -f docker/Dockerfile -t $(CONTAINER):$(TAG) .
	docker tag $(CONTAINER):$(TAG) probely/$(CONTAINER):$(TAG)

push: docker
	docker push probely/$(CONTAINER):$(TAG)

clean:
	docker rm -f $(CONTAINER) 2>/dev/null || true
