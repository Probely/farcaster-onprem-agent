set -e

# Password change will be enforced after first login
F_USER="probely"
F_PASSWORD="changeme"

apk add bash shadow sudo

adduser -D ${F_USER} -s /bin/bash
echo "${F_USER}:${F_PASSWORD}" | chpasswd
passwd -e ${F_USER}

mkdir -pm 700 /home/${F_USER}
chown -R ${F_USER}:${F_USER} /home/${F_USER}

adduser ${F_USER} wheel

# Allow users on the wheel group to use sudo without password
echo "Defaults exempt_group=wheel" > /etc/sudoers
echo "%wheel ALL=NOPASSWD:ALL" >> /etc/sudoers
