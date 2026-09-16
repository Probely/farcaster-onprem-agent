# Live agent checks

These checks connect to the real API and agent hub. Install Docker with Compose and set `FARCASTER_AGENT_TOKEN` to a test agent token in your environment.

Run from the repository root. To test userspace mode through an HTTP proxy while blocking direct traffic:

```sh
HTTP_PROXY=proxy:8888 RUN_MODE=--user NET_MODE=tcp_proxy make test-agent
```

To test kernel mode, give the agent the `NET_ADMIN` capability:

```sh
HTTP_PROXY=proxy:8888 RUN_MODE=--kernel NET_ADMIN=NET_ADMIN NET_MODE=tcp_proxy make test-agent
```

`NET_MODE=tcp_proxy` blocks outbound UDP on ports 53 and 443, and direct TCP on port 443. The separate network container needs `NET_ADMIN` in both modes.

Check the logs to confirm the selected mode and the connection to the hub. Kernel mode falls back to userspace if the required kernel features are missing. Press Ctrl+C to stop; the Make target removes the test containers on exit.
