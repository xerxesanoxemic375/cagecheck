VERSION ?= dev

.PHONY: build build-linux build-all clean

build:
	CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/cagecheck ./cmd/cagecheck

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/cagecheck-linux-amd64 ./cmd/cagecheck

build-all:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/cagecheck-linux-amd64 ./cmd/cagecheck
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/cagecheck-linux-arm64 ./cmd/cagecheck

clean:
	rm -rf bin/
