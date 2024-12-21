FROM golang:1.23-bookworm AS builder

WORKDIR /app
COPY *.go go.mod go.sum ./
RUN go build -o proxyprobe

FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /app/proxyprobe .
COPY test-connectivity.sh .
RUN chmod +x test-connectivity.sh \
    && apt-get update -y \
    && apt-get install -y ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* 

ENTRYPOINT ["/app/test-connectivity.sh"]
