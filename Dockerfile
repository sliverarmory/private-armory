# Use the official golang alpine image
FROM golang:alpine3.19 as builder

RUN apk add --no-cache make

# Create a build environment
RUN mkdir -p /tmp/private-armory
ADD . /tmp/private-armory
WORKDIR /tmp/private-armory
RUN make
RUN cp "./armory-server" /opt/armory-server

# Final layer
FROM alpine:3.19
COPY --from=builder /opt/armory-server /opt/armory-server

WORKDIR /data
VOLUME [ "/data/armory-data" ]
ENTRYPOINT [ "/opt/armory-server" ]
