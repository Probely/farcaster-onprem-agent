FROM golang:1.24 as build
WORKDIR /src
COPY . .
# Build within module root so imports resolve
WORKDIR /src/farcaster-go
RUN CGO_ENABLED=0 go build -o /src/farcaster-go/echoserver ../tests/proxy/echoserver/main.go

FROM gcr.io/distroless/base-debian12
COPY --from=build /src/farcaster-go/echoserver /usr/local/bin/echoserver
ENTRYPOINT ["/usr/local/bin/echoserver"]

