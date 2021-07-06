FROM golang:1.14.4-alpine AS builder
WORKDIR /go/src/github.com/Portshift/klar/
COPY ./ ./
RUN CGO_ENABLED=0 go build -o klar .

FROM registry.access.redhat.com/ubi8
RUN yum install ca-certificates -y
RUN mkdir /licenses
COPY ./LICENSE /licenses/
RUN mkdir /app
COPY --from=builder /go/src/github.com/Portshift/klar/klar /app/
RUN chmod +x /app/klar
ENTRYPOINT ["/app/klar"]

# Build-time metadata as defined at http://label-schema.org
ARG BUILD_DATE
ARG VCS_REF
LABEL org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.name="klar" \
    org.label-schema.description="Simple tool to analyze images stored in a private or public Docker registry for security vulnerabilities using Clair" \
    org.label-schema.url="https://github.com/Portshift/klar" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/Portshift/klar"

### Required OpenShift Labels
ARG IMAGE_VERSION
LABEL name="klar" \
      vendor="Portshift" \
      version=${IMAGE_VERSION} \
      release=${IMAGE_VERSION} \
      summary="Integration of Clair and Docker Registry" \
      description="Simple tool to analyze images stored in a private or public Docker registry for security vulnerabilities using Clair"

USER 1000
