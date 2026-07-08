BINARY := doppler-backup
CMD    := ./cmd/doppler-backup
BINDIR := bin

.PHONY: all build install test vet fmt clean

all: build

build:
	go build -o $(BINDIR)/$(BINARY) $(CMD)

install:
	go install $(CMD)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -rf $(BINDIR)
