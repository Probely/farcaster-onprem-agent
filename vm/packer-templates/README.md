# Remote Agent Packer Templates

The "On-premises Agent" is a component of the Probely Farcaster infrastructure.
It allows Probely's cloud-based scanners to find vulnerabilities on customer on-premises applications.

# How to build

We use [Packer](https://packer.io) to build a virtual appliance. We support several types of builders, such as VirtualBox, and VMWare.

To build an Agent appliance using VirtualBox, run the following commands:

```bash
cd alpine-3.12
../build.sh virtualbox
```

After Packer finishes, you should have OVF and VMDK files available on the `output-virtualbox-iso` directory. Note that the output directory will be different, depending on the underlying VM hypervisor used to create the VM appliance.

# How to install

Simply import the resulting virtual machine into your virtualization solution manager. Afterwards, you must run a customer-specific installer that will be provided.

# Acknowlegdements

The packer templates are inspired by [packer-templates](https://github.com/maier/packer-templates). Our thanks to the original authors.
