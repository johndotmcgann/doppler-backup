BINARY  := doppler-backup
CMD     := ./cmd/doppler-backup
BINDIR  := bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.Version=$(VERSION)

.PHONY: all build install test vet fmt clean

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(BINARY) $(CMD)

install:
	go install -ldflags "$(LDFLAGS)" $(CMD)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -rf $(BINDIR)
