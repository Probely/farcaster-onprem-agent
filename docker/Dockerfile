FROM rust:alpine as rust_builder
RUN set -eux \
    && apk add --no-cache git build-base \
    && git clone https://github.com/sorz/moproxy \
    && cd moproxy \
    && cargo build --release


FROM golang:1.16-alpine as go_builder
ARG wg_go_tag=0.0.20210323
ARG wg_tools_tag=v1.0.20210315
ENV WITH_WGQUICK=yes
RUN set -eux \
    && apk add --update git build-base libmnl-dev iptables \
    && git clone https://git.zx2c4.com/wireguard-go \
    && cd wireguard-go \
    && git checkout -b $wg_go_tag \
    && make \
    && make install \
    && git clone https://git.zx2c4.com/wireguard-tools \
    && cd wireguard-tools \
    && git checkout -b $wg_tools_tag \
    && cd src \
    && make \
    && make install


FROM alpine:3.13
COPY ./bin/. /farcaster/bin/
COPY --from=go_builder /usr/bin/wireguard-go /usr/bin/wg* /usr/bin/
COPY --from=rust_builder /moproxy/target/release/moproxy /usr/bin
RUN set -eux \
    && umask 077 \
    && apk add --no-cache --update \
        bash libmnl iptables openresolv iproute2 dnsmasq bind-tools \
    && for d in bin etc lib run sbin; do mkdir -p /farcaster/"${d}"; done \
    && ln -s /secrets/farcaster/data/wg-tunnel.conf /farcaster/etc/ \
    && ln -s /secrets/farcaster/data/wg-gateway.conf /farcaster/etc/ \
    && rm -rf /var/run \
    && ln -s /run /var/run \
    && mkdir -p /secrets/farcaster/data \
    && chmod +x /farcaster/bin/* \
    && addgroup -S proxy && adduser -S proxy -G proxy

