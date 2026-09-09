.PHONY: all test vet build fmt
all: test vet build
fmt:
	gofmt -w $$(find . -name '*.go')
test:
	go test -race ./...
vet:
	go vet ./...
build:
	mkdir -p dist && go build -trimpath -ldflags "-s -w" -o dist/skgate ./cmd/skgate
