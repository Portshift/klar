FROM golang:1.14.0-alpine AS builder
WORKDIR /go/src/github.com/Portshift/klar/
COPY ./ ./
RUN CGO_ENABLED=0 go build -o klar .

FROM alpine:3.11.3
RUN apk add --no-cache ca-certificates
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
