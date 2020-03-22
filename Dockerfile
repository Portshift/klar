FROM golang:1.8-alpine as builder

FROM alpine:3.8

RUN apk add --no-cache ca-certificates

RUN mkdir -p /usr/local/portshift/

COPY ./klar /usr/local/portshift/

RUN chmod +x /usr/local/portshift/klar

ENTRYPOINT ["/usr/local/portshift/klar"]

# Build-time metadata as defined at http://label-schema.org
ARG BUILD_DATE
ARG VCS_REF
LABEL org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.name="klar" \
    #org.label-schema.description="" \
    org.label-schema.url="https://github.com/Portshift/klar" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/Portshift/klar"
