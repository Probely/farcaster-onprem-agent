ARG GO_BUILDER_BASE="golang:1.26-bookworm"
ARG FINAL_BASE="debian:12-slim"

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
ARG VERSION
ENV FARCASTER_VERSION=${VERSION}
RUN set -eux \
    && umask 077 \
    && apt-get update -y \
    && apt-get dist-upgrade -y \
    && apt-get install -y --no-install-suggests --no-install-recommends \
       bash \
       iptables \
       iproute2 \
       wireguard-tools \
       ca-certificates \
    && for d in bin etc lib run sbin; do mkdir -p /farcaster/"${d}"; done \
    && ln -s /run/farcaster/wg-tunnel.conf /farcaster/etc/ \
    && ln -s /run/farcaster/wg-gateway.conf /farcaster/etc/ \
    && rm -rf /var/run \
    && ln -s /run /var/run \
    && mkdir -m 0700 -p /secrets/farcaster/data \
    && chmod +x /farcaster/bin/* \
    && useradd --system --home-dir / --shell /bin/false farcaster \
    && useradd --system --home-dir / --shell /bin/false diag \
    && ln /usr/local/bin/farconn /usr/local/bin/diag \
    && chgrp diag /usr/local/bin/diag \
    && chmod g+s /usr/local/bin/diag \
    && apt-get clean \
    && rm -rf /var/lib/apt \
    && /usr/local/bin/farconn >/dev/null 2>&1 \
    && /usr/local/bin/farcasterd --help >/dev/null 2>&1

ENTRYPOINT ["/farcaster/bin/entrypoint.sh"]
