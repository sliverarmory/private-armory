FROM alpine:3.14

COPY --from=golang:1.18-alpine /usr/local/go/ /usr/local/go/

