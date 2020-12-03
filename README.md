# Overview

This document will guide you through the installation of the Farcaster Agent on your network.

The Farcaster Agent connects Probely to (the parts that you choose of) your on-premises
network.
This broadens Probely's vulnerability scanning capabilities to internal
applications.

After being installed on-premises, the Agent creates an encrypted and
authenticated tunnel, in which traffic flows securely between Probely and your
network.

The Agent is open-source, and the code is freely available
[here](https://github.com/probely/farcaster-onprem-agent).

The following diagram shows an example network topology depicting an on-premises
network, the Agent, the Agent Hub (where on-premises Agents connect to),
and Probely's infrastructure.

![Farcaster high-level network architecture](https://probely.com/assets/images/Farcaster-Onprem-Agent.png)

# Security considerations

Installing third-party software on a network carries an inherent risk.
Being security professionals ourselves, we are very aware of this; that is why
Probely is designed with a security mindset from the ground up.

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

* Services are containerized and run with the least required privileges.
* The Agent is built around
[Zero Trust Networks](https://www.oreilly.com/library/view/zero-trust-networks/9781491962183/)
design principles. All traffic is end-to-end encrypted between agents.
Even inside Probely's "internal" networks.
* The Agent has been hardened in several ways, from hardened kernel settings to
proper cryptographic algorithms choices, that meet modern security
recommendations.
* Probely has no administrative access to the Agent (e.g. root access on the Agent Virtual Machine).
* You can define custom firewall rules, and network access can be further restricted.
* The Agent does not listen on any public Internet port, reducing its attack
surface. Instead, it creates an outbound connection to Probely’s network.


**Simplicity**

* We are firm believers that simplicity enables security.
The Agent follows simple design decisions, and uses modern open-source standard
components, such as [Wireguard](https://www.wireguard.com/).
* The Agent has minimal network requirements. Typical network requirements,
such as public IP addresses, complex firewall rules are unnecessary or minimized.
* The Agent needs minimal hardware resources and is designed to scale easily.

# System Resources

The Agent is comprised of a set of Docker containers, which require relatively
little system resources.

The following table contains the recommended minimum system resources.

| CPU     | RAM     | Storage     |
| ------- | ------- | ----------- |
| 1       | 1 GB    | 5 GB        |

# Network Requirements

## Internal Network Service

The Agent requires a set of basic network services to exist on your network,
which are detailed in the table below.

| Name | Description                                                 |
| ---- | ----------------------------------------------------------- |
| DHCP | IP network details, routes, and DNS servers                 |
| DNS  | For resolving internal DNS records                          |

## Firewall rules

In the following table, we describe the required firewall rules.

We expect a NAT gateway on the network to allow the Agent to reach external
services.
To specify a port range, we use the `:` character. For example, `1024:2048`
means: *all ports from 1024 to 2048, inclusive*.

| Name           | Source     | Destination                          | Protocol     | Source Port          | Destination Port |
| -------------- | ---------- | -------------------------------------| ------------ | -------------------- | -------------------- |
| API            | `agent-ip` | `api.probely.com`<sup>3</sup>        | `TCP`        | `1024:65535`         | `443`                  |
| Farcaster      | `agent-ip` | `hub.farcaster.probely.com`          | `UDP`        | `1024:65535`         | `443`                  |
| NTP            | `agent-ip` | `any`                                | `UDP`        | `any`                | `123`                  |
| DNS            | `agent-ip` | `<internal-dns-resolvers>`           | `TCP`, `UDP` | `any`                | `53`                   |
| DHCP           | `agent-ip` | `any`                                | `UDP`        | `67:68`              | `67:68`                |
| Scan           | `agent-ip` | `<scan-target>`<sup>1</sup>          | `TCP`        | `1024:65535`         | `<target-port>`<sup>2</sup>    |
| Docker         | `agent-ip` | `registry.docker.io`<sup>3</sup>     | `TCP`        | `1024:65535`         | `443`                  |
| Update servers | `agent-ip` | `dl-cdn.alpinelinux.org`<sup>3</sup> | `TCP`        | `1024:65535`         | `80`, `443`              |

Notes:

1. `<scan-target>` is the internal IP of your web application. 
If your target is configured to use internal extra-hosts, you must include their IPs here.
The same goes if the target login URL is served from a different internal web application.
2. `<target-port>` is the service port of the server of your web application.
Typical values are 80 and 443.
3. The IP addresses of these hosts are subject to change. We recommend allowing 
web access for the agent VM (http and https ports). If this is not possible, the agent VM
can use an http proxy server to reach the web. The proxy can be set in the `/etc/environment`
file.

# Installation

We provide three methods to deploy the Agent on your network.
Please note that only option **1** is officially supported, and has
seen the most testing.

1. **Using a pre-built VM**.
The VM contains everything required to run the Agent.
This should be a simpler approach, if you already have a virtualization solution
running (Hyper-V, KVM, VirtualBox, VMWare, among others). This is the officially
supported method.

1. **Running the containers directly**.
If you have the infrastructure to run Docker containers.
(Docker, Podman, Kubernetes, OpenShift, among other), you can run the containers
directly. This option is not officially supported, but we would love to hear your feedback if
you are running the agent this way.

1. **Building the VM and containers from source**.
Building from source allows controlling every aspect of the Farcaster Agent.

## Option 1: Virtual Machine (recommended)

The Agent VM is packaged as a ZIP archive, containing an Open Virtual Format
(OVF) file, and a Virtual Machine Disk (VMDK).

You should be able to import the Agent VM on any modern virtualization solution.
If are having issues importing the VM, we are happy to provide you with a
custom Agent VM for your specific needs.

To install the Agent Virtual Machine, please follow these steps:

* Download the most recent Virtual Machine from the
[Releases](https://github.com/Probely/farcaster-onprem-agent/releases) page.
The VM archive name is `probely-onprem-agent-vm-<version>.zip`

* Import the OVF file into your virtualization solution

* Allocate the required system resources for the Agent VM, as defined in the
[System Resources](#system-resources) section

* After the VM boots, use the default Agent credentials to log in
(user: `probely`, password: `changeme`)

  You can log into the VM on the local console, or via SSH
  (IP is assigned via DHCP).
  The SSH server accepts connections from private IP address ranges only
  (see which ones below).
  This is done to mitigate compromises by SSH botnets, if an unconfigured
  Agent VM is accidentally exposed to the Internet.
  The allowed SSH client IP ranges are:

    * `10.0.0.0/8`
    * `172.16.0.0/12`
    * `192.168.0.0/16`

* After logging on the VM for the first time, change the default password.

  Be sure to choose a strong password. Ideally, you should disable password
  logins via SSH, and enforce authentication using public keys or certificates.
  Enabling SSH public-key authentication is outside the scope of this document,
  but we can assist you in doing so through the support channels.

* You should have been given a `probely-onprem-agent-<id>.run` file, which is an
installer script tailored to your specific Agent.

  The installer is password-protected.
  If you do not have the installer script, or its password, please contact
  Probely's support team.
  If you want to know how the installer is built and what it does, please refer
  to the [Installer](#installer) section.

* To configure the Agent, run the following commands on the Agent Virtual
Machine. Note that you will be prompted for a password
(`enter aes-256-cbc decryption password`):

  ```bash
  chmod +x ./probely-onprem-agent-<id>.run
  sudo ./probely-onprem-agent-<id>.run
  ```

  > If using an HTTP proxy to reach the Internet, you can instruct Docker
  > to pull container images through the proxy, by setting the `HTTP` or `HTTPS`
  > variables in the `/etc/environment` file. Afterwards, run these commands:
  >
  >  ```sh
  >  /etc/init.d/docker restart
  >  /etc/init.d/docker-compose.probely-onprem-agent restart
  >  ```

* Check that the Agent connected successfully

  After starting the Agent, it should link-up with Probely. Run the following command:

  ```bash
  sudo docker exec -ti tunnel /farcaster/bin/wg show wg-tunnel | grep "latest handshake"
  ```

  You should see a `latest handshake: N seconds/minutes ago` message.

  If so, **you can start scanning on-premises targets using Probely**

  If not, check if Wireguard is connecting to the agent Hub:
  
  ```bash
  sudo docker exec -ti tunnel /farcaster/bin/wg show wg-tunnel | grep "transfer"
  ````
  
  If the number of received bytes is 0 (`transfer: 0 B received, x B sent`), this strongly
  suggests that there is a network/firewall configuration issue.

  > If the Agent is not connecting, please ensure that your [firewall](#firewall-rules)
  > is properly configured.

## Option 2: Docker containers

Note: this option is not officially supported, and may require setting additional
options to work on some environments.

For optimal performance, you should run the the container on a host with kernel support
for [Wireguard](https://www.wireguard.com/install/).
If Wireguard support is not detected, the Agent will use
[boringtun](https://github.com/cloudflare/boringtun) as a fallback option.

You should have been given a `probely-onprem-agent-<id>.run` file, which is an
installer script tailored to your specific Agent. The installer is password-protected.
If you do not have the installer script, or its password, please contact
Probely's support team.
If you want to know how the installer is built and what it does, please refer
to the [Installer](#installer) section.

Bundled with the installer, there is an example `docker-compose.yml` file.
It may be used with [Docker Compose](https://docs.docker.com/compose/) to start
the agent.

You can also use the `docker-compose.yml` file as a reference to deploy the Agent
to a container orchestrator, such as [Kubernetes](https://kubernetes.io/).
We provide an example Agent Kubernetes deployment
[here](https://github.com/probely/farcaster-onprem-agent/tree/master/contrib/kubernetes/).
If you need help setting the Agent up on a Kubernetes cluster, please contact
Probely's support team.

Both [Docker](https://docs.docker.com/engine/install/) and
[Docker Compose](https://docs.docker.com/compose/install/) must be installed
for these instructions to work. Please follow this procedure on a VM with those
requirements met.

* Run the following commands to extract the Agent keys and configuration files
from the Agent installer. Note that you will be prompted for a password
(`enter aes-256-cbc decryption password`):

  ```bash
  chmod +x ./probely-onprem-agent-<id>.run
  ./probely-onprem-agent-<id>.run --noexec --target ./agent
  ```

* Start the Agent:

  ```bash
  cd ./agent
  ./setup.sh --local
  docker-compose up
  ```

* Check that the Agent connected successfully

  After starting the Agent, it should link-up with Probely. Run the following command:

  ```bash
  sudo docker exec -ti tunnel /farcaster/bin/wg show wg-tunnel | grep "latest handshake"
  ```

  You should see a `latest handshake: N seconds/minutes ago` message.

  If so, **you can start scanning on-premises targets using Probely.**

  If not, check if Wireguard is connecting to the agent Hub:
  
  ```bash
  sudo docker exec -ti tunnel /farcaster/bin/wg show wg-tunnel | grep "transfer"
  ````
  
  If the number of received bytes is 0 (`transfer: 0 B received, x B sent`), this strongly
  suggests that there is a network/firewall configuration issue.

  > If the Agent is not connecting, please ensure that your [firewall](#firewall-rules)
  > is properly configured.

## Option 3: Building from source

* Start by checking the code out from the repository:

  ```bash
  git clone git@github.com:Probely/farcaster-onprem-agent.git
  ```

**Unless otherwise specified, these instructions must be run on the repository
root.**

### Containers

* Build the containers:

  ```bash
  make docker
  ```

* Push the container images to your Docker registry. Check the `push` 
target on the provided [Makefile](/Makefile) for guidance.

Remember to reference your custom-built Docker images on any `docker-compose.yml`
file, or Kubernetes pod/deployment descriptor you configure. If not specified,
the default Probely docker Agent images are used.

### Installer

The installer build script expects a "config bundle" to exist. A config bundle
is a set of configuration files and keys that allow the Agent to connect to
Probely.

You should have been given a `probely-onprem-agent-<id>.run` file, which is an
installer script tailored to your specific Agent. The installer is password-protected.
If you do not have the installer script, or its password, please contact
Probely's support team.

* First, extract the Agent configuration bundle from the original installer.
Note that you will be prompted for a password (`enter aes-256-cbc decryption password`):

  ```bash
  chmod +x ./probely-onprem-agent-<id>.run
  ./probely-onprem-agent-<id>.run --noexec --target ./tmp/agent-installer
  ```

* Re-create the config bundle:

  ```bash
  tar -zcpvf ./tmp/<id>.tar.gz -C ./tmp/agent-installer/secrets .
  ```

The installer build script will ask you for a password to secure the secrets. 
Please choose a strong password.

* Create the new installer:

  ```bash
  ./installer/make-installer.sh ./tmp/<id>.tar.gz
  ```

The new installer will be placed in `installer/target/probely-onprem-agent-<id>.run`.

* Finally, run the instaler.

The installer reads the `DOCKER_IMAGE` environment variable. You can use it to
specify your custom-built Docker images:

  ```bash
  sudo DOCKER_IMAGE=<custom_image_url> ./installer/target/probely-onprem-agent-<id>.run
  ```

### Virtual machine
We use [Packer](https://packer.io) to build the Agent VM.

Currently, we support the following builder types:

* VirtualBox
* VMWare
* XEN
* KVM

If you need to build the Agent VM image on a virtualization platform different
from the ones we currently support, please contact Probely's support.

For example, to build the Agent VM using the VirtualBox builder, follow these steps:

* Install [Packer](https://www.packer.io/intro/getting-started/install.html)
* Run these commands:

  ```bash
  cd vm/packer-templates/alpine3.12
  ../build.sh virtualbox
  ```

After Packer finishes building the VM, you should have OVF and VMDK files
available on the `output-virtualbox-iso` directory. Note that the output
directory name and contents may differ, depending on the underlying VM builder
you chose to create the VM.

You can now install the VM using the steps described in the Virtual Machine
installation section. If applicable, remember to use your custom
[installer](#installer).
