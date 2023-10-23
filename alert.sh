#!/bin/bash

# MIT License

# https://www.shellcheck.net/wiki/SC2112
# https://www.shellcheck.net/wiki/SC2049

# Thanks to the following projects for code, ideas, and guidance:
# https://github.com/g0tmi1k/OS-Scripts
# https://github.com/angristan/openvpn-install

# Path to the log to monitor
LOG_AUTH='/var/log/auth.log'
LOG_SUDO='/var/log/auth.log'
LOG_AUDIT='/var/log/audit/audit.log'

# Webhook URL
# This can be seen by anyone on the system by running `ps aux` at the right time
# https://www.cyberciti.biz/faq/linux-hide-processes-from-other-users/
WEBHOOK='paste-your-webhook-here'

IsRoot() {

	# Root EUID check
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi

}
IsRoot

PostLogEntry() {

	# Send the information in json format as a POST request, this is formatted for Discord
	# https://discord.com/developers/docs/resources/webhook#execute-webhook-jsonform-params
	curl -X POST -H 'Content-type: application/json' -d '{"content":"'"$log_entry"'"}' "$WEBHOOK"

}

# Monitor the log(s) for new entries even if it rotates
# https://superuser.com/questions/270529/monitoring-a-file-until-a-string-is-found

# Call the PostLogEntry function to send entries to the webhook that match our regex
# The '=~' matches POSIX extended regular expression
# https://stackoverflow.com/questions/19441521/bash-regex-operator
# https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html#Conditional-Constructs

# Replace or add functions with relevant log strings and processing
# Log monitors are separated into individual functions to run simultaneously in the background

MonitorAuthLogs() {

	tail -n 0 -F "$LOG_AUTH" | while read -r log_entry; do
		# Match on "Accepted" which is generally an SSH authentication
		if [[ "$log_entry" =~ "Accepted" ]]; then
			PostLogEntry "$log_entry"
		fi
	done

}

MonitorSudoLogs() {

	tail -n 0 -F "$LOG_AUTH" | while read -r log_entry; do
		# Match on sudo usage captured in auth.log
		# Note this will POST the full command line arguments to Discord
		if [[ "$log_entry" =~ "sudo" ]]; then
			PostLogEntry "$log_entry"
		fi
	done
}

MonitorAuditLogs() {

	tail -n 0 -F "$LOG_AUDIT" | ausearch -i | while read -r log_entry; do
		# Match auditd key entries
		# This currently has issues as is when making the POST request, it requires another, successful, POST request for it to go through
		# [Laurel](https://github.com/threathunters-io/laurel) may be the best option here if it's a size constraint
		if [[ "$log_entry" =~ "T1219_Remote_Access_Software" ]]; then
			PostLogEntry "$log_entry"
		fi
	done

}

RunMonitoring() {

	# The trick is to let the final process run in the foreground, so it can be managed as an active systemd service.
	# There may be a better way to do this with the service configuration
	# All active functions above the bottom function should have an '&' appended, like this if "MonitorAuditLogs" is the bottom function:
	# MonitorAuthLogs &
	# MonitorSudoLogs &
	# MonitorAuditLogs

	MonitorAuthLogs
#	MonitorSudoLogs
#	MonitorAuditLogs

}
RunMonitoring
