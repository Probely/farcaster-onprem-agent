# AGENTS.md

## Repository overview

Farcaster connects Snyk API & Web to private networks through a WireGuard tunnel. See [README.md](README.md) for installation, configuration, and troubleshooting.

There are two agent implementations:

- The kernel-based agent uses Linux WireGuard, iptables, and dnsmasq. Shell scripts in `scripts/` manage it. The Go helper in `farconn/` downloads configuration and provides network diagnostics. This mode needs the `NET_ADMIN` capability.
- The userspace-based agent is `farcasterd`, built from `farcaster-go/`. It uses WireGuard in Go and the gVisor network stack. It can run without `NET_ADMIN`, in a container or as a standalone process on Linux, macOS, and Windows.

The root container includes both implementations. `scripts/entrypoint.sh` defaults to kernel mode and falls back to userspace if the kernel checks or startup fail. Set `RUN_MODE=--user` to select userspace mode explicitly.

| Path | Contents |
| --- | --- |
| `scripts/` | Container entrypoint, kernel startup in `run.sh`, userspace startup in `run-user.sh`, and shared helpers in `_lib.sh`. |
| `farcaster-go/` | Userspace agent: CLI and service setup in `cmd/farcasterd/`, lifecycle in `agent/`, proxies in `dialers/`, and tunnels and network forwarding in `wireguard/`. |
| `farconn/` | Configuration and diagnostic CLI used by the kernel agent. |
| `tests/` | Docker Compose setups for proxy integration tests and live agent checks. |
| `contrib/` | Kubernetes and OpenShift deployment examples, plus the separate `proxyprobe/` diagnostic tool. |

## Build

Use the Go version required by each module's `go.mod`. The Go modules are `farcaster-go/`, `farconn/`, and `contrib/proxyprobe/`. There is no root Go module or `go.work`; run Go commands inside the module you are changing.

Run these commands from the repository root:

```sh
make -C farcaster-go VERSION=0.0.0
make -C farconn
```

The binaries are written to `farcaster-go/bin/farcasterd` and `farconn/farconn`.

To build the root container locally, use Docker with Buildx:

```sh
make VERSION=0.0.0 build-local
```

The root `make build` and `make build-modern` targets push images to Docker Hub. The `build-local` variants load images locally, but their `prepare` step runs a privileged container to install binfmt handlers and configures a Buildx builder. Use publishing targets only for release work.

## Tests and checks

Install Go, GNU Make, Bash, and ShellCheck. Run from the repository root:

```sh
make check
```

This runs shell syntax checks, ShellCheck, shell helper tests, and Go vet and tests in all three modules. Use `make check-shell` or `make check-go` to run one group. Install golangci-lint v2 and use `make lint` to check for Go lint issues introduced since `origin/main` in the userspace agent.

[CI](.github/workflows/ci.yml) runs `make check`, checks for new Go lint issues, and runs a separate vulnerability check for `farcaster-go/`.

`TestAgentLifecycle` connects to a real service when `FARCASTER_AGENT_TOKEN` is set. `make check-go` unsets that token. Proxy integration tests skip when their endpoint environment variables are missing.

For proxy or dialer changes, run the Docker Compose integration tests:

```sh
make test-proxy
ENFORCE_PROXY=true make test-proxy
```

The second run blocks direct traffic inside the test container. These tests need Docker Compose and container `NET_ADMIN`. The target cleans up containers on exit. The tests use local services and do not need an agent token.

`make test-agent` runs live agent checks and needs a test agent token. See [tests/agent/README.md](tests/agent/README.md) for the proxy setup. Check both `RUN_MODE=--kernel` with `NET_ADMIN=NET_ADMIN` and `RUN_MODE=--user` when changing shared startup behavior. Confirm the selected mode in the logs because kernel mode can fall back to userspace.

## Code conventions

- Keep changes focused. Reuse existing helpers and the standard library before adding dependencies. Avoid speculative abstractions and unrelated cleanup. Do not reformat existing documentation without a content reason. There is no prose line-length limit.
- Format Go with `gofmt`. Return errors with useful context and handle each error once. Comments should explain reasons or constraints that the code cannot show.
- Test observable behavior. Follow the existing table-driven Go tests and use small test helpers. Add tests in proportion to the risk of the change.
- Preserve customer-facing flags, environment variables, proxy behavior, and supported platforms unless the task calls for a compatibility change. Keep Windows-specific code in the existing platform files.
