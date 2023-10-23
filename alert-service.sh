#!/bin/bash

# MIT License

# Thanks to the following projects for code, ideas, and guidance:
# https://github.com/g0tmi1k/OS-Scripts
# https://github.com/angristan/openvpn-install
# https://github.com/bettercap/bettercap/blob/master/bettercap.service

# Colors
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings
BLUE="\033[01;34m"     # Information
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

function IsRoot() {

	# Root EUID check
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi

}
IsRoot

function CheckPath() {

	SCRIPT_PATH='/opt/scripts/alert.sh'
	# Check to see if alert.sh exists
	if ! [ -e "$SCRIPT_PATH" ]; then
		echo "Missing $SCRIPT_PATH. Quitting."
		exit 1
	fi
	
	# If the script exists, ensure the correct permissions are applied
	# Only root should have read access to this file because the webhook must exist in plain text
	chmod 700 "$SCRIPT_PATH" || exit 1

}
CheckPath

# Check to see if this service is already running
if [ -e /etc/systemd/system/alert-service.service ]; then
	systemctl status alert-service.service
	echo ""
	echo -e "[${BLUE}i${RESET}]Service already exists. Reconfigure and overwrite it?"
	until [[ $RECONFIGURE_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]: " -e -i y RECONFIGURE_CHOICE
	done
	if [ "$RECONFIGURE_CHOICE" == y ]; then
		if (systemctl is-active alert-service.service > /dev/null); then
			systemctl stop alert-service.service
		fi
		if (systemctl is-enabled alert-service.service > /dev/null); then
			systemctl disable alert-service.service
		fi
		rm /etc/systemd/system/alert-service.service && \
		systemctl daemon-reload
	else
		exit 0
	fi
fi

# cat /etc/systemd/system/alert-service.service
# Uses https://github.com/bettercap/bettercap/blob/master/bettercap.service as a template
# Also see: https://github.com/angristan/openvpn-install/blob/80feebed16b3baa5979f764ee3272443f2fe08e6/openvpn-install.sh#L1001C4-L1001C4
echo "[Unit]
Description=Post log entries to webhooks
Documentation=https://github.com/straysheep-dev/alert-service
Wants=network.target
After=network.target

[Service]
Type=simple
PermissionsStartOnly=true
ExecStart=/bin/bash /opt/scripts/alert.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/alert-service.service

echo ""
echo -e "[${BLUE}i${RESET}]Reloading all systemctl service files..."
echo ""
systemctl daemon-reload && \
echo -e "[${BLUE}i${RESET}]Enabling alert-service.service..."
echo ""
systemctl enable alert-service.service && \
echo -e "[${BLUE}i${RESET}]Starting alert-service.service"
echo ""
systemctl start alert-service.service && \
echo -e "[${GREEN}✓${RESET}]Done."
echo ""
systemctl status alert-service.service
