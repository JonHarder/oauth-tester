build:
	go build ./cmd/oauth-server

install:
	go install ./cmd/oauth-server

test:
	go test ./...
