FROM --platform=$BUILDPLATFORM rust as rust_builder
ENV moproxy_tag=v0.3.10
ENV udp_over_tcp_tag=v0.2.0
ARG TARGETARCH
RUN set -eux \
    && { [ "${TARGETARCH}" = "arm64" ] && TARGETARCH="aarch64" || TARGETARCH="x86-64"; } \
    && RUST_TARGET="$(echo $TARGETARCH | tr '-' '_')" \
    && apt-get update -y \
    && apt-get install -y git libc-dev gcc-${TARGETARCH}-linux-gnu binutils-${TARGETARCH}-linux-gnu \
    # moproxy \
    && git clone https://github.com/sorz/moproxy \
    && cd moproxy \
    && git checkout -b tags/$moproxy_tag \
    && rustup target add ${RUST_TARGET}-unknown-linux-gnu \
    && env CARGO_TARGET_$(echo ${RUST_TARGET} | tr [:lower:] [:upper:])_UNKNOWN_LINUX_GNU_LINKER="${RUST_TARGET}-linux-gnu-gcc-10" cargo build --release --target ${RUST_TARGET}-unknown-linux-gnu \
    && mkdir -p target/release \
    && cp target/${RUST_TARGET}-unknown-linux-gnu/release/moproxy target/release \
    # udp-over-tcp \
    && cd / \
    && git clone https://github.com/Probely/udp-over-tcp.git \
    && cd udp-over-tcp \
    && git checkout -b tags/$udp_over_tcp_tag \
    && rustup target add ${RUST_TARGET}-unknown-linux-gnu \
    && env \
        CARGO_TARGET_$(echo ${RUST_TARGET} | tr [:lower:] [:upper:])_UNKNOWN_LINUX_GNU_LINKER="${RUST_TARGET}-linux-gnu-gcc-10" \
        cargo build --release --target ${RUST_TARGET}-unknown-linux-gnu \
        --features env_logger --features structopt --bins \
    && mkdir -p target/release \
    && cp target/${RUST_TARGET}-unknown-linux-gnu/release/udp2tcp target/release


FROM --platform=$BUILDPLATFORM golang:1.18 as go_builder
COPY ./diag /build/diag
ARG wg_go_tag=0.0.20220316
ARG TARGETARCH
RUN set -eux \
    && mkdir -p /build \
    && cd /build \
    && apt-get update -y \
    && apt-get install -y git libc-dev gcc libmnl-dev iptables \
    && git clone https://git.zx2c4.com/wireguard-go \
    && cd wireguard-go \
    && git checkout tags/${wg_go_tag} -b ${wg_go_tag} \
    && env GOOS=linux GOARCH=$TARGETARCH make \
    && env GOOS=linux GOARCH=$TARGETARCH make install \
    && cd - \
    && cd diag \
    && env GOOS=linux GOARCH=$TARGETARCH make \
    && cd -


FROM debian:bullseye-slim
COPY ./bin/. /farcaster/bin/
COPY --from=go_builder /usr/bin/wireguard-go /usr/bin/
COPY --from=go_builder /build/diag/diag /usr/local/bin/
COPY --from=rust_builder /moproxy/target/release/moproxy /usr/local/bin
COPY --from=rust_builder /udp-over-tcp/target/release/udp2tcp /usr/local/bin
RUN set -eux \
    && umask 077 \
    && apt-get update -y \
    && apt-get install -y --no-install-suggests --no-install-recommends \
       bash \
       libmnl0 \
       iptables \
       openresolv \
       iproute2 \
       dnsmasq \
       dnsutils \
       curl \
       wireguard-tools \
    && apt-get clean \
    && update-alternatives --set iptables /usr/sbin/iptables-legacy \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy \
    && for d in bin etc lib run sbin; do mkdir -p /farcaster/"${d}"; done \
    && ln -s /run/farcaster/wg-tunnel.conf /farcaster/etc/ \
    && ln -s /run/farcaster/wg-gateway.conf /farcaster/etc/ \
    && rm -rf /var/run \
    && ln -s /run /var/run \
    && mkdir -p /secrets/farcaster/data \
    && chmod +x /farcaster/bin/* \
    && { useradd --system --home-dir / --shell /bin/false proxy || true; } \
    && useradd --system --home-dir / --shell /bin/false diag \
    && useradd --system --home-dir / --shell /bin/false tcptun \
    && chgrp diag /usr/local/bin/diag \
    && chmod g+s /usr/local/bin/diag \
    # Make sure that binaries were properly built
    && /usr/local/bin/moproxy --help >/dev/null 2>&1 \
    && /usr/local/bin/udp2tcp --help >/dev/null 2>&1 \
    && /usr/local/bin/diag >/dev/null 2>&1 \
    && /usr/bin/wireguard-go >/dev/null 2>&1

