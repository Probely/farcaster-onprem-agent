set -eux

apk add openssh-server-pam

# SSH root login was allowed so that Packer provisioners could work
# Remove it, as it is no longer required
sed -i '/^PermitRootLogin yes/d' /etc/ssh/sshd_config
