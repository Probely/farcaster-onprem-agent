# Overview

This document will guide you through the installation of the Farcaster Agent on your network.

The Farcaster Agent connects Probely to your on-premises network, using an encrypted WireGuard
tunnel, allowing Probely to scan your internal applications.

The Agent is open-source, and the code is freely available
[here](https://github.com/probely/farcaster-onprem-agent).

The following diagram shows an example network topology depicting an on-premises
network, the Agent, the Agent Hub (where on-premises Agents connect to),
and Probely's infrastructure.

![Farcaster high-level network architecture](https://probely.com/assets/media/img_farcaster.png)

# Security considerations

Installing third-party software on your network requires some degree of trust.
Being security professionals ourselves, we are very aware of this, and designed
Probely with a security mindset.

We designed the Agent following a set of principles that we believe will meet
your security expectations.

**Transparency**

* No black boxes: all code is open source, with a permissive license.
* In addition to the source code, the instructions and tools to build the Agent
are provided.
With them, you can ensure that the Agent running on your infrastructure has not
been tampered with.
* You have complete control over the Agent, and can change any of its components
however you see fit.

**Least privilege**

* Services are containerized and run with least privileges.
* The Agent is built around
[Zero Trust Networks](https://www.oreilly.com/library/view/zero-trust-networks/9781491962183/)
design principles. All traffic is end-to-end encrypted between agents.
Even inside Probely's "internal" networks.
* The Agent has been hardened in several ways, from choosing memory-safe languages
(e.g. Go and Rust) to modern, recommended, cryptographic algorithms.
* Probely has no administrative access to the Agent running on your infrastructure
* The Agent does not listen on any public Internet port, reducing its attack
surface. Instead, it creates an outbound connection to Probely’s network.

**Simplicity**

* We are firm believers that simplicity enables security.
The Agent follows simple design decisions, and uses modern open-source standard
components, such as [WireGuard](https://www.wireguard.com/).
* The Agent has minimal network requirements. Typical network requirements,
such as public IP addresses, complex firewall rules are unnecessary or minimized.
* The Agent needs minimal hardware resources and is designed to scale easily.

# System Resources

The Agent is a simple Docker container requiring little resources.

The following table contains the recommended minimum system resources.

| CPU     | RAM     | Storage     |
| ------- | ------- | ----------- |
| 1       | 1 GB    | 5 GB        |

# Network Requirements

In the following table, we describe the required firewall rules.

We expect a NAT gateway (or an HTTP proxy) to exist on the network
for the Agent to reach Probely's servers.

To specify a port range, we use the `:` character. For example, `1024:2048`
means: *all ports from 1024 to 2048, inclusive*.

| Name           | Source     | Destination                          | Protocol     | Source Port          | Destination Port |
| -------------- | ---------- | -------------------------------------| ------------ | -------------------- | -------------------- |
| API            | `agent-ip` | `api.probely.com`<sup>3</sup>        | `TCP`        | `1024:65535`         | `443`                  |
| Tunnel         | `agent-ip` | `hub.farcaster.probely.com`          | `UDP`        | `1024:65535`         | `443`                  |
| DNS            | `agent-ip` | `<internal-dns-resolvers>`           | `TCP`, `UDP` | `any`                | `53`                   |
| Scan           | `agent-ip` | `<scan-target>`<sup>1</sup>          | `TCP`        | `1024:65535`         | `<target-port>`<sup>2</sup>    |
| OOB Vulnerability Check <sup>5</sup> | `agent-ip`, `target-ip` | `52.17.201.157`| `TCP`, `UDP`| `*`                  | `*`    |
| Docker         | `agent-ip` | `auth.docker.io`, `registry*.docker.io`<sup>3</sup>     | `TCP`        | `1024:65535`         | `443`        |

Notes:

1. `<scan-target>` is the internal IP of your web application. 
If your target is configured to use internal extra-hosts, you must include their IPs here.
The same goes if the target login URL is served from a different internal web application.
2. `<target-port>` is the service port of the server of your web application.
Typical values are 80 and 443.
3. The IP addresses of these hosts are subject to change. We recommend allowing 
web access for the agent VM (HTTP and HTTPS ports). If this is not possible, the agent
can use an HTTP proxy server to reach the web.
4. At this time, the hosts are: `registry.docker.io` and `registry-1.docker.io`
5. This server receives connections from potentially vulnerable systems on your infrastructure.
It is used, for example, to detect "Log4Shell"-type vulnerabilities.

# Installation

The agent is a simple Docker container. It should run on any system with a working Docker installation.

You should have a `probely-onprem-agent-<id>.run` file, which is an
installer script tailored to your specific Agent.

> If you do not have an installer, you can create one in the
> [Scanning Agents](https://plus.probely.app/scanning-agents/) management area.
> If you want to know how the installer is built and what it does, please refer
> to the [Installer](#installer) section.

## Required software

Both [Docker](https://docs.docker.com/engine/install/) and
[Docker Compose](https://docs.docker.com/compose/install/) must be installed
for these instructions to work. Please follow this procedure on a VM with those
requirements met.

## Kubernetes (optional)
We provide an example Agent Kubernetes deployment
[here](https://github.com/probely/farcaster-onprem-agent/tree/master/contrib/kubernetes/).
If you need help setting the Agent up on a Kubernetes cluster, please contact
Probely's support team.

## System checks
* Before installing the agent container, check that your host can run it:
  ```bash
  curl -LO https://raw.githubusercontent.com/Probely/farcaster-onprem-agent/master/diag/host-check.sh
  chmod +x host-check.sh
  ./host-check.sh
  ```

  Verify that the checks succeeded:
  ```bash
  Checking if Docker is installed...                              [ok]
  Launching test container...                                     [ok]
  ```

* Run the following commands to extract the Agent keys and configuration files
from the Agent installer:

  ```bash
  chmod +x ./probely-onprem-agent-<id>.run
  ./probely-onprem-agent-<id>.run --noexec --target ./agent
  ```

* Start the Agent:

  ```bash
  cd ./agent
  ./setup.sh
  docker-compose up
  ```

* Check that the Agent connected successfully

  After starting the Agent, it should link-up with Probely. Run the following command:
  ```bash
  sudo docker logs -ti probely-agent
  ```
  If everything is running correctly, you should see an output similar to:
  ```bash
  $ docker-compose up
  Creating network "agent_default" with the default driver
  Creating probely-agent ... done
  Attaching to probely-agent
  probely-agent | Starting local DNS resolver     ... done
  probely-agent | Setting HTTP proxy rules        ... done
  probely-agent | Connecting to Probely           ... done
  probely-agent | Setting local gateway rules     ... done
  probely-agent | Starting WireGuard gateway      ... done
  probely-agent |
  probely-agent | Running..
  ```

  > If the Agent is not connecting, please ensure that your [firewall](#firewall-rules)
  > are properly configured.

# Building from source

Note: this option is not officially supported, and may require setting additional options to work on some environments.

* Start by checking the code out from the repository:

  ```bash
  git clone git@github.com:Probely/farcaster-onprem-agent.git
  ```

**Unless otherwise specified, these instructions must be run on the repository
root.**

* Build the container:

  ```bash
  VERSION=local make build-local
  ```

Remember to reference your custom-built Docker images on any `docker-compose.yml`
file, or Kubernetes pod/deployment descriptor you configure. If not specified,
the default Probely docker Agent images are used.

### Installer

The installer build script expects a "config bundle" to exist. A config bundle
is a set of configuration files and keys that allow the Agent to connect to
Probely.

You should have a `probely-onprem-agent-<id>.run` file, which is an
installer script tailored to your specific Agent.

If you do not have an installer, you can create one in the
[Scanning Agents](https://plus.probely.app/scanning-agents/) management area.

* First, extract the Agent configuration bundle from the original installer:
  ```bash
  chmod +x ./probely-onprem-agent-<id>.run
  ./probely-onprem-agent-<id>.run --noexec --target ./tmp/agent-installer
  ```

* Re-create the config bundle:

  ```bash
  tar -zcpvf ./tmp/<id>.tar.gz -C ./tmp/agent-installer/secrets .
  ```

* Create the new installer:

  ```bash
  ./installer/make-installer.sh ./tmp/<id>.tar.gz
  ```

The new installer will be placed in `installer/target/probely-onprem-agent-<id>.run`.

