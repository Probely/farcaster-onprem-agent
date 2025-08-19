FROM golang:1.24 as build
WORKDIR /src
COPY . .
# Build within module root so imports resolve
WORKDIR /src/farcaster-go
RUN CGO_ENABLED=0 go build -o /src/farcaster-go/proxytest ../tests/proxy/runner/main.go

FROM debian:12-slim
RUN apt-get update && apt-get install -y iptables dnsutils && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/farcaster-go/proxytest /usr/local/bin/proxytest
COPY tests/proxy/runner/proxy-enforcer.sh /usr/local/bin/proxy-enforcer.sh
RUN chmod +x /usr/local/bin/proxy-enforcer.sh
ENTRYPOINT ["/usr/local/bin/proxy-enforcer.sh"]

