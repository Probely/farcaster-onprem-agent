# Example run

- Forbid UDP, force userspace mode with proxy

```
env HTTP_PROXY=proxy:8888 FARCASTER_AGENT_TOKEN=xxx NET_ADMIN=NET_ADMIN NET_MODE=tcp docker compose up --build
```
