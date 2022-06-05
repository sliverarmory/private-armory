FROM alpine:3.16

COPY --from=golang:1.18-alpine /usr/local/go/ /usr/local/go/
RUN apk add --no-cache make

RUN mkdir -p /tmp/external-armory \
    && mkdir -p /data
ADD . /tmp/external-armory
WORKDIR /tmp/external-armory
RUN GOOS=linux make .
WORKDIR /opt

# Cleanup
RUN rm -rf /tmp/external-armory \
    && rm -rf /usr/local/go

VOLUME [ "/data/armory-root" ]
ENTRYPOINT [ "/opt/external-armory" ]
