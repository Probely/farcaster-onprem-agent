variable "alpine_ver" {
  type    = string
  default = "3.14"
}

variable "alpine_rel" {
  type    = string
  default = "3.14.0"
}

variable "cpus" {
  type    = number
  default = 1
}

variable "disk_size" {
  type    = number
  default = 5120
}

variable "memory" {
  type    = number
  default = 512
}

variable "disk_dev" {
  type    = string
  default = "sda"
}

locals {
  vm_name = "probely-onprem-agent"

  iso_cksum = "d568c6c71bb1eee0f65cdf40088daf57032e24f1e3bd2cf8a813f80d2e9e4eab"
  iso_url   = "http://dl-cdn.alpinelinux.org/alpine/v${var.alpine_ver}/releases/x86_64/alpine-virt-${var.alpine_rel}-x86_64.iso"

  boot_command = [
    "root<enter><wait>",
    "ifconfig eth0 up && udhcpc -i eth0<enter><wait10s>",
    "wget http://{{ .HTTPIP }}:{{ .HTTPPort }}/answers<enter><wait>",
    "sed -i s#__DISK_DEVICE__#/dev/${var.disk_dev}# $PWD/answers<enter><wait>",
    "setup-alpine -f $PWD/answers<enter><wait30s>",
    "only-used-during-build<enter><wait>",
    "only-used-during-build<enter><wait>",
    "<wait30s>",
    "y<enter>",
    "<wait120s>",
    "rc-service sshd stop<enter>",
    "mount /dev/${var.disk_dev}2 /mnt<enter>",
    "echo 'PermitRootLogin yes' >> /mnt/etc/ssh/sshd_config<enter>",
    "umount /mnt<enter>",
    "reboot<enter>"
  ]

  scripts = [
    "scripts/00base.sh",
    "scripts/02sshd.sh",
    "scripts/03users.sh",
    "scripts/05docker.sh",
    "scripts/90virt.sh",
    "scripts/91harden.sh",
    "scripts/97farcaster.sh",
    "scripts/98minimize.sh",
    "scripts/99disable-root.sh"
  ]
}

source "qemu" "vm" {
  vm_name          = local.vm_name
  boot_command     = local.boot_command
  accelerator      = "tcg"
  boot_wait        = "60s"
  communicator     = "ssh"
  disk_size        = var.disk_size
  format           = "qcow2"
  disk_compression = true
  headless         = false
  http_directory   = "http"
  iso_checksum     = "sha256:${local.iso_cksum}"
  iso_urls         = [local.iso_url]
  net_device       = "virtio-net"
  disk_interface   = "virtio-scsi"
  shutdown_command = "/sbin/poweroff"
  ssh_password     = "only-used-during-build"
  ssh_timeout      = "10m"
  ssh_username     = "root"
}

source "virtualbox-iso" "vm" {
  vm_name          = local.vm_name
  boot_command     = local.boot_command
  boot_wait        = "30s"
  communicator     = "ssh"
  disk_size        = var.disk_size
  format           = "ova"
  guest_additions_mode = "disable"
  guest_os_type    = "Linux26_64"
  headless         = false
  http_directory   = "http"
  iso_checksum     = "sha256:${local.iso_cksum}"
  iso_urls         = [local.iso_url]
  shutdown_command = "/sbin/poweroff"
  ssh_password     = "only-used-during-build"
  ssh_timeout      = "10m"
  ssh_username     = "root"
}

build {
  description = "Probely Alpine Linux x86_64"
  sources     = ["source.qemu.vm"]

  provisioner "shell" {
    scripts = local.scripts
  }
}
