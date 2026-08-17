FROM golang:1.24-alpine AS builder

# The release this image is built from, stamped into the binary and reported by
# /-/version and `-version`. CI passes the same string it tags the image with,
# so a running pod names the exact image to pull.
#
# It has to be passed in: .dockerignore excludes .git and only sources are
# copied below, so Go's automatic VCS stamping has no repository to read. The
# default keeps a bare `docker build .` honest rather than mislabeled.
ARG VERSION=dev

# Needed at runtime for the optional HTTPS organization lookup (?org=1).
RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/asn-ipv6-ranges .

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/asn-ipv6-ranges /asn-ipv6-ranges

USER 65532:65532
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/asn-ipv6-ranges"]
