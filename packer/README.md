# On-premises Agent Packer Templates

The "On-premises Agent" is a component of the Probely Farcaster infrastructure.
It allows Probely's cloud-based scanners to find vulnerabilities on customer on-premises applications.

# How to build

We use [Packer](https://packer.io) to build a virtual appliance. Make sure it is installed.

To build an Agent VM disk image, run the following commands:

```bash
cd alpine
make
```

# How to install

Create a Virtual Machine and import the disk image
