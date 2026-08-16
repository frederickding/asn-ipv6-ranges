FROM golang:1.24-alpine AS builder

# Needed at runtime for the optional HTTPS organization lookup (?org=1).
RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY go.mod ./
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/asn-ipv6-ranges .

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/asn-ipv6-ranges /asn-ipv6-ranges

USER 65532:65532
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/asn-ipv6-ranges"]
