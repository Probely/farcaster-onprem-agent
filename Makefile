CONTAINER=farcaster-onprem-agent

.PHONY: all docker push clean ssh_configs

docker:
	docker build -f docker/Dockerfile -t $(CONTAINER) .
	docker tag $(CONTAINER):latest probely/$(CONTAINER):latest

push: docker
	docker push probely/$(CONTAINER):latest

clean:
	docker rm -f $(CONTAINER) 2>/dev/null || true
