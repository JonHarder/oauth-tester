FROM golang:1.18-alpine AS build
ENV GOOS linux
ENV CGO_ENABLED 0
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN go build -buildvcs=false -o /oauth-server ./cmd/oauth-server

FROM scratch AS bin
ARG PORT
EXPOSE ${PORT}
COPY --from=build /oauth-server /oauth-server
COPY public /public
ENTRYPOINT ["/oauth-server"]
