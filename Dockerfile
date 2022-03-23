FROM golang:1.17-alpine AS build
ENV GOOS linux
ENV CGO_ENABLED 0
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN go build -o /oauth-server ./cmd/oauth-server

FROM scratch AS bin
EXPOSE 8001
COPY --from=build /oauth-server /oauth-server
COPY static /static
COPY config.json .
ENTRYPOINT ["/oauth-server"]
