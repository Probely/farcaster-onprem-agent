#!/usr/bin/env bash

build_conf="build.conf"

function die_var_unset {
    echo "ERROR: Variable '$1' is required to be set. Please edit '${build_conf}' and set."
    exit 1
}

function help {
    echo "$0 <kvm|virtualbox|vmware|xen>"
    echo
    echo "kvm          - build VM using KVM"
    echo "virtualbox   - build VM using VirtualBox"
    echo "vmware       - build VM using VMWare"
    echo "xen          - build VM using Xen"
    exit 1
}

PACKER=$(type -P packer)
[[ $? -eq 0 && -n "$PACKER" ]] || { echo "Unable to find 'packer' command"; exit 1; }

target=${1:-}
[[ -z "$target" ]] && help

case $target in
    kvm)
        echo "Building VM using KVM"
        VM_BUILDER="qemu"
        VM_TYPE="kvm"
        ;;
    virtualbox)
        echo "Building VM using VirtualBox"
	    VM_BUILDER="virtualbox-iso"
        ;;
    vmware)
        echo "Building VM using VMware"
	    VM_BUILDER="vmware-iso"
        ;;
    xen)
        echo "Building VM using Xen"
        VM_BUILDER="qemu"
        VM_TYPE="xen"
        ;;
    *)
        help
        ;;
esac

[[ -f $build_conf ]] || { echo "User variables file '$build_conf' not found."; exit 1; }

source $build_conf

[[ -z "$dist_name" ]] && die_var_unset "dist_name"
[[ -z "$dist_vers" ]] && die_var_unset "dist_vers"
[[ -z "$dist_rel" ]] && die_var_unset "dist_rel"
[[ -z "$dist_arch" ]] && die_var_unset "dist_arch"
[[ -z "$VM_NAME" ]] && VM_NAME="${dist_name}-${dist_vers}-${dist_arch}"
[[ -z "$VM_VERSION" ]] && VM_VERSION="${dist_vers}"
[[ -z "$VM_RELEASE" ]] && VM_RELEASE="${dist_rel}"

template_name="${VM_NAME}.json"

[[ -f $template_name ]] || { echo "Template (${template_name}) not found."; exit 1; }

export VM_TAG=$VM_NAME
export VM_VER=$VM_VERSION
export VM_REL=$VM_RELEASE
export VM_BUILDER
export VM_TYPE

$PACKER build --only=$VM_BUILDER $template_name

unset VM_REL
unset VM_VER
unset VM_TAG
unset VM_BUILDER
unset VM_TYPE
