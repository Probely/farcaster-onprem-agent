FROM golang:1.26-bookworm as build
WORKDIR /src
COPY . .
# Run tests within module so imports resolve
WORKDIR /src/farcaster-go
RUN CGO_ENABLED=0 go test ./integration/proxy -c -o /testrunner

FROM debian:12.14-slim
RUN apt-get update && apt-get dist-upgrade -y && apt-get install -y iptables dnsutils && rm -rf /var/lib/apt/lists/*
COPY --from=build /testrunner /usr/local/bin/testrunner
COPY tests/proxy/runner/proxy-enforcer.sh /usr/local/bin/proxy-enforcer.sh
RUN chmod +x /usr/local/bin/proxy-enforcer.sh
ENTRYPOINT ["/usr/local/bin/proxy-enforcer.sh"]
CMD ["/usr/local/bin/testrunner", "-test.v"]


