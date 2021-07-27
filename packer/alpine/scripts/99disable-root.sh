set -eux

# Disable the root account. Packer provisioners have run.
sed -i 's/^root:[^:]:\(.*$\)/root:\*:\1/' /etc/shadow
