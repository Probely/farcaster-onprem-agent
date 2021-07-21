.DEFAULT_GOAL := build

fmt:
	go fmt ./...

lint: fmt
	golint ./...

vet: fmt
	go vet ./...

build: vet
	go build -o diag main.go

.PHONY: fmt lint vet build
