# Example run

- Forbid UDP
- Forbid direct UDP

```
env HTTP_PROXY=proxy:8888 FARCASTER_AGENT_TOKEN=xxx RUN_MODE=--user NET_ADMIN=NET_ADMIN NET_MODE=tcp_proxy docker compose up --build
```
