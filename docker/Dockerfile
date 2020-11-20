FROM rust:slim AS rust_builder
WORKDIR /build
RUN set -eux \
    && umask 077 \
    && apt-get update \
    && apt-get install -y \
        --no-install-recommends --no-install-suggests \
        git \
    && git clone https://github.com/cloudflare/boringtun.git \
    && cd boringtun \
    && cargo build --release \
    && strip ./target/release/boringtun

FROM debian:buster-slim AS builder
WORKDIR /build
COPY ./builder/. /build/
RUN set -eux \
	&& umask 077 \
    && echo "deb http://deb.debian.org/debian/ unstable main" | \
		tee /etc/apt/sources.list.d/unstable-wireguard.list \
    && printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' | \
        tee /etc/apt/preferences.d/limit-unstable \
    && apt-get update \
    && apt-get install -y \
        --no-install-recommends --no-install-suggests \
        wireguard-tools \
        binutils \
    && for d in bin etc lib run sbin; do mkdir -p /farcaster/"${d}"; done \
    && ./install-iptables.sh /farcaster \
    && ./install-dnsmasq.sh /farcaster \
    && ./install-bash.sh /farcaster \
    && ./install-dnsutils.sh /farcaster \
    && ln -s /secrets/farcaster/data/wg-tunnel.conf /farcaster/etc/ \
    && ln -s /secrets/farcaster/data/wg-gateway.conf /farcaster/etc/ \
    && cp -a /usr/bin/wg* /farcaster/bin/ \
    && (strip /farcaster/bin/* || true)

FROM gcr.io/distroless/base-debian10:debug
COPY --from=builder /farcaster/. /farcaster/
COPY --from=rust_builder /build/boringtun/target/release/boringtun /farcaster/bin/
COPY --from=rust_builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/libgcc_s.so.1
COPY ./bin/. /farcaster/bin/
RUN ["/busybox/sh", "-c", "set -eux \
    && umask 077 \
    && rm -rf /var/run \
    && ln -s /run /var \
    && mkdir -p /secrets/farcaster/data \
    "]
