.PHONY: build run clean

build:
	docker build -t proxyprobe .

run:
	docker run --rm \
		-e HTTP_PROXY="$(HTTP_PROXY)" \
		-e HTTPS_PROXY="$(HTTPS_PROXY)" \
		-e SOCKS_PROXY="$(SOCKS_PROXY)" \
		proxyprobe

clean:
	docker rmi proxyprobe
