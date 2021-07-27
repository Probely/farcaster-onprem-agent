set -e

cat << 'EOF' > /etc/init.d/farcaster-setup
#!/sbin/openrc-run

description="Run tasks required for Farcaster connectivity"

depend() {
	before net
	after sysctl
	use logger
}

start() {
	ebegin "Starting Farcaster setup tasks"
	_start_vm_tools
	_limit_ssh_connections
	eend $?
}

stop() {
	ebegin "Cleaning up Farcaster setup tasks"
}

_start_vm_tools() {
	vm_type=$(dmidecode -s system-product-name | tr '[:upper:]' '[:lower:]')

	case ${vm_type} in
		vmware*)
			/etc/init.d/open-vm-tools start
			;;
		virtualbox*)
			/etc/init.d/virtualbox-guest-additions start
			;;
	esac
}

_limit_ssh_connections() {
	ip_ranges="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
	for ip_range in ${ip_ranges}; do
		iptables -t filter -A INPUT -p tcp --dport 22 -s ${ip_range} -j ACCEPT
	done
	iptables -t filter -A INPUT -p tcp --dport 22 -j DROP
}
EOF

chmod +x /etc/init.d/farcaster-setup
rc-update add farcaster-setup default

# Helper that checks if the host can launch farcaster containers
curl -L https://raw.githubusercontent.com/probely/farcaster-onprem-agent/master/diag/host-check.sh > /usr/local/bin/host-check
chmod +x /usr/local/bin/host-check

# Shortcut for farcaster container internal sanity check tool
cat << 'EOF' > /usr/local/bin/diag
#!/bin/sh
if !(docker exec -ti gateway ls >/dev/null 2>&1); then
	echo "Error - the farcaster gateway container does not seem to be running:"
	echo "  * Please run 'host-check' to check if host requirements are met"
	echo "  * Make sure that the farcaster containers are installed"
	exit 1
fi
exec docker exec -ti gateway $@
EOF
chmod +x /usr/local/bin/diag
