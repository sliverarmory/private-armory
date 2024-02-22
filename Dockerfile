# Use the official golang alpine image
FROM golang:alpine3.19

RUN apk add --no-cache make

# Create a build environment
RUN mkdir -p /tmp/external-armory
ADD . /tmp/external-armory
WORKDIR /tmp/external-armory
RUN GOOS=linux make external-armory
RUN cp external-armory /opt

# Cleanup
RUN rm -rf /tmp/external-armory \
    && rm -rf /usr/local/go

WORKDIR /data

VOLUME [ "/data/armory-data" ]

ENTRYPOINT [ "/opt/external-armory" ]
