#!/usr/bin/env python

# GPL-2.0 (C) 2015, Wazuh Inc.
# GPL-2.0 (C) 2024, straysheep-dev

# Based on the integration files here: https://github.com/wazuh/wazuh/blob/master/integrations/
#
# IMPORTANT: you will likely need to copy (any one) of the shell scripts under /var/ossec/integrations/<script>
# and name it custom-discord.
# They're all the same script, just different file names, copy one so you have custom-discord (the shell script)
# and custom-discord.py (this script) in that folder together. The shell script is used to execute the python script.
# Ensure both files are set to '0750' and owned by 'root:wazuh'
#
# Jira guide: https://wazuh.com/blog/how-to-integrate-external-software-using-integrator/
# Wazuh Docs: https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html

# Run manually for debugging with:
# python3 ./custom-discord.py 'test.json' '' '<webhook>' 'debug'
# Where test.json is a file containing a single log entry (it does not have to be a single line, just one log entry) for testing purposes.

# This integration is meant to be as generic and universal as possible, for sending Wazuh alerts to Discord as rich embeds.
# The alert fields try to account for all use cases, syslog, auditd, and sysmon(+forlinux) to ship a reasonable amount
# of data for any given event.
# This is tricky, with custom decoders and specific events, you can have varying fields.
# The work around is conditional variables, and conditional fields. If an arbitary field is not found in a log, it either returns
# a value to a key that's always present, or if the key's empty the default value of N/A. In other cases it may skip the key entirely.
# Conditional fields also determine what's sent. If it's an auditd log, the fields for Sysmon data are absent.
#
# This creates multiple areas for fine-grained filtering. There's also a SKIP_RULE_IDS list where rules to skip can be added.
# The idea though is to primarily use the <integration> section in ossec.conf to filter what this integration ships.


import json
import os
import sys

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ossec.conf configuration structure
# Ideally, you are limiting this based on group, rule id, severtiy, and log location.
# This integration will work with basically any log type Wazuh has, so the block can be duplicated in ossec.conf
# to focus on different uses and filters.
#  <integration>
#      <name>custom-discord</name>
#      <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXX</hook_url>
#      <group>GROUP</group> <!-- Replace with an optional comma separated list of groups or remove it -->
#      <rule_id>RULE_ID</rule_id> <!-- Replace with an optional comma separated list of rule ids or remove it -->
#      <level>SEVERITY_LEVEL</level> <!-- Replace with an optional minimum severity level or remove it -->
#      <event_location>EVENT_LOCATION</event_location> <!-- Replace with an optional comma separated list of event locations or remove it -->
#      <alert_format>json</alert_format>
#      <options>JSON</options> <!-- Replace with your custom JSON object or remove it -->
#  </integration>

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}

# Rule filter
# This is just one additional place to fine tune what alerts are posted
SKIP_RULE_IDS = [
    '00000',
]

# Log path
LOG_FILE = f'{pwd}/logs/integrations.log'
#LOG_FILE = f'integrations.log'  # Use when manually debugging

# Constants
ALERT_INDEX = 1
WEBHOOK_INDEX = 3


def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments: bool = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1], args[2], args[3], args[4] if len(args) > 4 else '', args[5] if len(args) > 5 else ''
            )
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            msg = '# ERROR: Wrong arguments'
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

        if bad_arguments:
            debug('# ERROR: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        # Core function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args) -> None:
    """This is the core function, creates a message with all valid fields
    and overwrite or add with the optional fields

    Parameters
    ----------
    args : list[str]
        The argument list from main call
    """
    debug('# Running Discord script')

    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    webhook: str = args[WEBHOOK_INDEX]
    options_file_location: str = ''

    # Look for options file location
    for idx in range(4, len(args)):
        if args[idx][-7:] == 'options':
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    debug('# Generating message')
    msg: any = generate_msg(json_alert, json_options)

    if not len(msg):
        debug('# ERROR: Empty message')
        raise Exception

    debug(f'# Sending message {msg} to Discord server')
    send_msg(msg, webhook)


def debug(msg: str) -> None:
    """Log the message in the log file with the timestamp, if debug flag
    is enabled

    Parameters
    ----------
    msg : str
        The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


def filter_msg(alert) -> bool:
    # From https://github.com/wazuh/wazuh/blob/a5f51ad61af5abcf49186cd72d4d73c0c3927021/integrations/shuffle.py#L166
    # Skips any rule ID listed in SKIP_RULE_IDS above.
    # This is the same rule_id variable from the generate_msg() function, just below
    rule_id = alert['rule']['id'] if 'id' in alert['rule'] else 'N/A'
    return rule_id not in SKIP_RULE_IDS


def generate_msg(alert: any, options: any) -> str:
    """Generate the JSON object with the message to be send

    Parameters
    ----------
    alert : any
        JSON alert object.
    options: any
        JSON options object.

    Returns
    -------
    msg: str
        The JSON message to send
    """

    # Discord intro to webhooks: https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks
    # Discord webhook / embed usage: https://discord.com/safety/using-webhooks-and-embeds
    # Discord embed object structure: https://discord.com/developers/docs/resources/channel#embed-object
    # Discord embed field structure: https://discord.com/developers/docs/resources/channel#embed-object-embed-field-structure
    # Additional references:
    # - https://github.com/eugenio-chaves/eugenio-chaves.github.io/blob/main/blog/2022/creating-a-custom-wazuh-integration/index.md#customizing-the-script
    # - https://github.com/maikroservice/wazuh-integrations/blob/main/discord/custom-discord.py

    # IMPORTANT:
    # When debugging using raw JSON logs, be sure to copy JSON data from the "Dashboard" view, instead of the "Events" view. You'll see
    # the entire JSON structure is prepended with a few fields, including "_source". This will break the variables below, as Wazuh already
    # "sees" those keys as metaFields and parses them correctly when using this script.

    # Conditional Variables (syntax is very simialr to Ansible's 'when:' conditional thanks to python)
    # All variables were moved here for readability, and have nested conditional statements to account for different log strucutres, ending in some
    # cases with a default of 'N/A' to catch if none are true.
    # The conditionals are also meant to avoid KeyErrors (https://docs.python.org/3/library/exceptions.html#KeyError) for missing
    # keys in arbitrary JSON structures.
    # This integration was tested using auditd, Sysmon, and sysmonforlinux, with the following Wazuh rules and decoder files from SOCFortress
    # - https://github.com/socfortress/Wazuh-Rules/tree/main/Auditd
    # - https://github.com/socfortress/Wazuh-Rules/tree/main/Sysmon%20Linux
    # - The built in decoder and rules were used for Sysmon (on Windows)
    timestamp = alert['timestamp'] if 'timestamp' in alert else 'N/A'
    severity = alert['rule']['level']
    description = alert['rule']['description'] if 'description' in alert['rule'] else 'N/A'
    agent_id = alert['agent']['id'] if 'id' in alert['agent'] else 'N/A'
    agent_name = alert['agent']['name'] if 'name' in alert['agent'] else 'N/A'
    rule_id = alert['rule']['id'] if 'id' in alert['rule'] else 'N/A'
    location = alert['location']
    dest_ip = alert['data']['eventdata']['DestinationIp'] if 'data' in alert and 'eventdata' in alert['data'] and 'DestinationIp' in alert['data']['eventdata'] else 'N/A'
    dest_port = alert['data']['eventdata']['destinationPort'] if 'data' in alert and 'eventdata' in alert['data'] and 'destinationPort' in alert['data']['eventdata'] else 'N/A'
    dest_host = alert['data']['eventdata']['destinationHostname'] if 'data' in alert and 'eventdata' in alert['data'] and 'destinationHostname' in alert['data']['eventdata'] else 'N/A'
    src_ip = alert['data']['eventdata']['sourceIp'] if 'data' in alert and 'eventdata' in alert['data'] and 'sourceIp' in alert['data']['eventdata'] else 'N/A'
    src_port = alert['data']['eventdata']['sourcePort'] if 'data' in alert and 'eventdata' in alert['data'] and 'sourcePort' in alert['data']['eventdata'] else 'N/A'
    full_log = alert['full_log'] if 'full_log' in alert else 'N/A'
    win_message = alert['data']['win']['system']['message'] if 'data' in alert and 'win' in alert['data'] and 'system' in alert['data']['win'] and 'message' in alert['data']['win']['system'] else 'N/A'
    log_id = alert['id']

    # Rule filter to skip rules in SKIP_RULE_IDS
    if not filter_msg(alert):
        print('Skipping rule %s' % rule_id)
        return ''

    # Discord colors take the decimal value of the color's hex code (https://discord.com/developers/docs/resources/channel#embed-object-embed-structure)
    # You can Google a color's hex code, open a calculator app in programming mode, set it to HEX mode, and paste the
    # hex value. Change it to DEC mode to get the decimal representation of that hex code. That is the value to use here.
    if severity <= 4:
        color = '255' # blue, hex value is #0000FF
    elif severity >= 5 and severity <= 7:
        color = '16776960' # yellow, hex value is #FFFF00
    else:
        color = '16711680' # red, hex value is #FF0000

    msg = {}
    msg['type'] = 'rich' # Discord specific, default type for embeds
    msg['color'] = color
    msg['title'] = 'WAZUH Alert'
    msg['description'] = description

    msg['fields'] = []
    # The 'if' statements wrapping certain fields determine if a field exists in the log data, and if not, that
    # field will be absent entirely in the embed rather than an empty field.
    # Discord embeds can include up to 25 fields. 'inline' means it will attempt to put neighboring fields into one line,
    # up to three per row.
    msg['fields'].append(
        {
            'name': 'Timestamp',
            'value': '{0}'.format(timestamp),
            'inline': False
        }
    )
    if 'agent' in alert:
        msg['fields'].append(
            {
                'name': 'Agent',
                'value': '({0}) - {1}'.format(agent_id, agent_name),
                'inline': True
            }
        )
    if 'agentless' in alert:
        msg['fields'].append(
            {
                'name': 'Agentless Host',
                'value': '{0}'.format(agentless),
                'inline': True
            }
        )
    msg['fields'].append(
        {
            'name': 'Location',
            'value': '{0}'.format(location),
            'inline': True
        }
    )
    msg['fields'].append(
        {
            'name': 'Rule ID',
            'value': '{0} _(Level {1})_'.format(rule_id, severity),
            'inline': True
        }
    )
    # The remaining fields have been formatted with a code block using one ` or three ``` backticks to prevent malicious strings from potentially
    # making network requests or being clickable
    if 'data' in alert and 'eventdata' in alert['data'] and 'DestinationIp' in alert['data']['eventdata']:
        msg['fields'].append(
            {
                'name': 'Dest IP',
                'value': '`{0}`'.format(dest_ip),
                'inline': True
            }
        )
    if 'data' in alert and 'eventdata' in alert['data'] and 'destinationPort' in alert['data']['eventdata']:
        msg['fields'].append(
            {
                'name': 'Dest Port',
                'value': '`{0}`'.format(dest_port),
                'inline': True
            }
        )
    if 'data' in alert and 'eventdata' in alert['data'] and 'destinationHostname' in alert['data']['eventdata']:
        msg['fields'].append(
            {
                'name': 'Dest Host',
                'value': '`{0}`'.format(dest_host),
                'inline': True
            }
        )
    if 'data' in alert and 'eventdata' in alert['data'] and 'sourceIp' in alert['data']['eventdata']:
        msg['fields'].append(
            {
                'name': 'Source IP',
                'value': '`{0}`'.format(src_ip),
                'inline': True
            }
        )
    if 'data' in alert and 'eventdata' in alert['data'] and 'sourcePort' in alert['data']['eventdata']:
        msg['fields'].append(
            {
                'name': 'Source Port',
                'value': '`{0}`'.format(src_port),
                'inline': True
            }
        )
    if 'full_log' in alert:
        msg['fields'].append(
            {
                'name': 'Full Log',
                'value': '```{0}```'.format(full_log),
                'inline': False
            }
        )
    if 'data' in alert and 'win' in alert['data'] and 'system' in alert['data']['win'] and 'message' in alert['data']['win']['system']:
        msg['fields'].append(
            {
                'name': 'Message',
                'value': '```{0}```'.format(win_message),
                'inline': False
            }
        )
    msg['fields'].append(
        {
            'name': 'Wazuh ID',
            'value': '{0}'.format(log_id),
            'inline': False
        }
    )

    if options:
        msg.update(options)

    payload = {'embeds': [msg]}
    if options:
        payload.update(options)

    return json.dumps(payload)


def send_msg(msg: str, url: str) -> None:
    """Send the message to the API

    Parameters
    ----------
    msg : str
        JSON message.
    url: str
        URL of the API.
    """
    headers = {'content-type': 'application/json'}
    res = requests.post(url, data=msg, headers=headers, timeout=10)
    debug('# Response received: %s' % res.json)


def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    FileNotFoundError
        If no JSON file is found.
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location: str) -> any:
    """Read JSON options object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# JSON file for options %s doesn't exist" % file_location)
    except BaseException as e:
        debug('Failed getting JSON options. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)