# Installing the Agent on an OpenShift Cluster

1. Go to the [Scanning Agents](https://plus.probely.app/scanning-agents/) page.
   Create an agent and take note of the **agent token**.
2. Create the `probely` namespace
   ```shell
   oc create namespace probely
   ```
3. Create the `agent token` secret
   ```shell
   oc -n probely create secret generic farcaster-secrets \
     --from-literal=token=<YOUR_AGENT_TOKEN>
   ```
4. Deploy the agent pod
   ```shell
   oc apply -f https://raw.githubusercontent.com/Probely/farcaster-onprem-agent/main/contrib/openshift/probely-agent-depl.yaml
   ```
5. Check that the agent is working properly
   ```shell
   oc -n probely logs -f farcaster-agent-<id>
   ```
   You should see output similar to:
   ```
   Starting local DNS resolver     ... done
   Setting HTTP proxy rules        ... done
   Connecting to Probely           ... done
   Setting local gateway rules     ... done
   Starting WireGuard gateway      ... done

   Running...
   ```
