# Installing the Agent on a Kubernetes Cluster

In this directory, we provide two Kubernetes deployment manifests:
  * `probely-agent-depl.yaml`: this is the recommended way to use the agent. Use it if your kernel version if >= 5.6
  * `probely-agent-fallback-depl.yaml`: use this manifest to install the agent on older kernels.

The rest of this document assumes a recent kernel.

1. Go to the [Scanning Agents](https://plus.probely.app/scanning-agents/) page. Create and download your agent installer
2. Extract the Agent keys:
   ```shell
   ./probely-onprem-agent-<agent_id>.run --noexec --target ./agent
   ```
3. Deploy the agent keys on the cluster
   ```shell
   kubectl create namespace farcaster
   cd agent/secrets/kubernetes
   kubectl -n farcaster apply -f farcaster-secrets.yaml 
   ````
4. Deploy the agent pods
  ```shell
  git clone https://github.com/Probely/farcaster-onprem-agent.git
  cd farcaster-onprem-agent/contrib/kubernetes
  kubectl -n farcaster apply -f probely-agent-depl.yaml
  ```
5. Check that the agent is working properly
  ```shell
  kubectl -n farcaster logs -f probely-onprem-agent-<id> -c gateway
  ```
  You should see output similar to:
  ```shell
  Setting up firewall and NAT rules       ... done
  Starting local DNS resolver     ... done
  Checking if a proxy is required ... done
  Starting WireGuard connections  ... done
  
  Running...
  ```
