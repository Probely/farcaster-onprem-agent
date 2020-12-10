set -ux

# Add community repo
echo http://dl-cdn.alpinelinux.org/alpine/v3.12/community >> /etc/apk/repositories

apk upgrade -U --available

# Base packages
apk add apk-cron curl dmidecode patch

source /etc/os-release

cat << EOF > /etc/motd

$PRETTY_NAME ($VERSION_ID) Probely Farcaster On-Premises Agent

See the Alpine Wiki for how-to guides and
general information about administrating
Alpine systems and development.
See <http://wiki.alpinelinux.org>

EOF

cat << EOF >> /etc/modules
tun
veth
wireguard
nf_tables
nft_chain_nat
nft_compat
nft_counter
xt_nat
EOF
