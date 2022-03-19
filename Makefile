build:
	go build ./cmd/oauth-server

install:
	go install ./cmd/oauth-server

test:
	go test ./...

dev:
	CompileDaemon -build="go build ./cmd/oauth-server" -command="./oauth-server"
