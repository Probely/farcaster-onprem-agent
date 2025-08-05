ARG RUST_BUILDER_BASE="rust:1-bullseye"
ARG GO_BUILDER_BASE="golang:1.24-bullseye"
ARG FINAL_BASE="debian:12.10-slim"
ARG GCC_VERSION="10"

FROM --platform=$BUILDPLATFORM ${RUST_BUILDER_BASE} AS rust_builder
ENV moproxy_tag=v0.5.1
ENV udp_over_tcp_tag=v0.4.0
ARG TARGETARCH
ARG GCC_VERSION
RUN set -eux \
    && { [ "${TARGETARCH}" = "arm64" ] && TARGETARCH="aarch64" || TARGETARCH="x86-64"; } \
    && RUST_TARGET="$(echo $TARGETARCH | tr '-' '_')" \
    && apt-get update -y \
    && apt-get dist-upgrade -y \
    && apt-get install -y git libc-dev gcc-${TARGETARCH}-linux-gnu binutils-${TARGETARCH}-linux-gnu \
    # moproxy \
    && git clone https://github.com/sorz/moproxy \
    && cd moproxy \
    && git checkout -b tags/$moproxy_tag \
    && rustup target add ${RUST_TARGET}-unknown-linux-gnu \
    && env CARGO_TARGET_$(echo ${RUST_TARGET} | tr [:lower:] [:upper:])_UNKNOWN_LINUX_GNU_LINKER="${RUST_TARGET}-linux-gnu-gcc-${GCC_VERSION}" cargo build --release --target ${RUST_TARGET}-unknown-linux-gnu \
    && mkdir -p target/release \
    && cp target/${RUST_TARGET}-unknown-linux-gnu/release/moproxy target/release \
    # udp-over-tcp \
    && cd / \
    && git clone https://github.com/Probely/udp-over-tcp.git \
    && cd udp-over-tcp \
    && git checkout -b tags/$udp_over_tcp_tag \
    && rustup target add ${RUST_TARGET}-unknown-linux-gnu \
    && env \
        CARGO_TARGET_$(echo ${RUST_TARGET} | tr [:lower:] [:upper:])_UNKNOWN_LINUX_GNU_LINKER="${RUST_TARGET}-linux-gnu-gcc-${GCC_VERSION}" \
        cargo build --release --target ${RUST_TARGET}-unknown-linux-gnu \
        --features env_logger --features clap --bins \
    && mkdir -p target/release \
    && cp target/${RUST_TARGET}-unknown-linux-gnu/release/udp2tcp target/release


FROM --platform=$BUILDPLATFORM ${GO_BUILDER_BASE} AS go_builder
COPY ./farconn /build/farconn
COPY ./farcaster-go /build/farcaster-go
ARG TARGETARCH
ARG VERSION
RUN set -eux \
    && mkdir -p /build \
    && cd /build \
    && apt-get update -y \
    && apt-get dist-upgrade -y \
    && apt-get install -y git libc-dev gcc libmnl-dev iptables \
    \
    && cd farconn \
    && env GOOS=linux GOARCH=$TARGETARCH make build-fast \
    && cd - \
    && cd farcaster-go \
    && env VERSION=${VERSION} GOOS=linux GOARCH=$TARGETARCH make \
    && cd -


FROM ${FINAL_BASE}
COPY ./scripts/. /farcaster/bin/
COPY --from=go_builder /build/farconn/farconn /usr/local/bin
COPY --from=go_builder /build/farcaster-go/bin/farcasterd /usr/local/bin
COPY --from=rust_builder /moproxy/target/release/moproxy /usr/local/bin
COPY --from=rust_builder /udp-over-tcp/target/release/udp2tcp /usr/local/bin
ARG VERSION
ENV FARCASTER_VERSION=${VERSION}
RUN set -eux \
    && umask 077 \
    && apt-get update -y \
    && apt-get dist-upgrade -y \
    && apt-get install -y --no-install-suggests --no-install-recommends \
       bash \
       libmnl0 \
       iptables \
       iproute2 \
       dnsmasq \
       dnsutils \
       wireguard-tools \
       ca-certificates \
       ipcalc \
    && apt-get clean \
    && for d in bin etc lib run sbin; do mkdir -p /farcaster/"${d}"; done \
    && ln -s /run/farcaster/wg-tunnel.conf /farcaster/etc/ \
    && ln -s /run/farcaster/wg-gateway.conf /farcaster/etc/ \
    && rm -rf /var/run \
    && ln -s /run /var/run \
    && mkdir -m 0700 -p /secrets/farcaster/data \
    && chmod +x /farcaster/bin/* \
    && { useradd --system --home-dir / --shell /bin/false proxy || true; } \
    && useradd --system --home-dir / --shell /bin/false diag \
    && useradd --system --home-dir / --shell /bin/false tcptun \
    && ln /usr/local/bin/farconn /usr/local/bin/diag \
    && chgrp diag /usr/local/bin/diag \
    && chmod g+s /usr/local/bin/diag \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt \
    # Make sure that binaries were properly built
    && /usr/local/bin/moproxy --help >/dev/null 2>&1 \
    && /usr/local/bin/udp2tcp --help >/dev/null 2>&1 \
    && /usr/local/bin/farconn >/dev/null 2>&1 \
    && /usr/local/bin/farcasterd --help >/dev/null 2>&1

ENTRYPOINT ["/farcaster/bin/entrypoint.sh"]