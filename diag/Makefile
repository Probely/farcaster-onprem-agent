.DEFAULT_GOAL := build
BIN := diag

fmt:
	go fmt ./...

lint: fmt
	golint ./...

vet: fmt
	go vet ./...

build: vet
	go build -o $(BIN) main.go

clean:
	rm -rf $(BIN)

.PHONY: fmt lint vet build clean
