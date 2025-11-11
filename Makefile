# CPW - Clipboard Password Manager Makefile

.PHONY: build install clean test

# Build the binary
build:
	go build -o cpw main.go

# Install to local GOPATH/bin
install:
	go install

# Clean build artifacts
clean:
	rm -f cpw

# Run tests (placeholder for future tests)
test:
	go test ./...

# Build for multiple platforms
build-all:
	GOOS=darwin GOARCH=amd64 go build -o cpw-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 go build -o cpw-darwin-arm64 main.go
	GOOS=linux GOARCH=amd64 go build -o cpw-linux-amd64 main.go
	GOOS=windows GOARCH=amd64 go build -o cpw-windows-amd64.exe main.go

# Default target
all: build