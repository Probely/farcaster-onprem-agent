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
