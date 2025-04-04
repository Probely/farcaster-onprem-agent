FROM --platform=$BUILDPLATFORM golang:1.24 as go_builder
COPY . /build/
ARG TARGETARCH
ARG VERSION
RUN set -eux \
    && mkdir -p /build \
    && cd /build \
    && apt-get update -y \
    && env GOOS=linux GOARCH=${TARGETARCH} make

FROM debian:bookworm-slim
COPY --from=go_builder /build/bin/farcasterd /usr/local/bin/farcasterd
RUN set -eux \
    && apt-get update -y \
    && apt-get dist-upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    # Make sure that binaries were properly built
    && /usr/local/bin/farcasterd --help >/dev/null 2>&1

USER nobody
ENTRYPOINT ["/usr/local/bin/farcasterd"]