FROM alpine:3.16

COPY --from=golang:1.18-alpine /usr/local/go/ /usr/local/go/

RUN mkdir -p /tmp/external-armory
ADD . /tmp/external-armory
WORKDIR /tmp/external-armory
RUN CGO_ENABLED=0 GOOS=linux /usr/local/go/bin/go build -trimpath -o /opt/external-armory .
WORKDIR /opt

# Cleanup
RUN rm -rf /tmp/external-armory \
    && rm -rf /usr/local/go


VOLUME [ "/opt/armory-root" ]
ENTRYPOINT [ "/opt/external-armory" ]
