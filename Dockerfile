FROM golang:1.8-alpine as builder

FROM alpine:3.8

RUN apk add --no-cache ca-certificates

RUN mkdir -p /usr/local/portshift/

COPY ./klar /usr/local/portshift/

RUN chmod +x /usr/local/portshift/klar

ENTRYPOINT ["/usr/local/portshift/klar"]
