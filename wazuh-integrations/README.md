# wazuh integrations

This is a custom integration for shipping alerts to Discord via an embed / webhook.

 <img src=./media/wazuh_integration_discord_2.png width="385" /> <img src=./media/wazuh_integration_discord_3.png width="500" />

Examples of this [already](https://github.com/eugenio-chaves/eugenio-chaves.github.io/blob/main/blog/2022/creating-a-custom-wazuh-integration/index.md#customizing-the-script) [exist](https://github.com/maikroservice/wazuh-integrations/blob/main/discord/custom-discord.py), making great points of reference to build and revise your own integration. However this port does a few things differently.

- Uses the existing [slack.py `generate_msg`](https://github.com/wazuh/wazuh/blob/a5f51ad61af5abcf49186cd72d4d73c0c3927021/integrations/slack.py#L132) function's code and overall formatting with conditional fields
- Adds conditional fields that will be included with certain Sysmon / sysmonforlinux events
- Includes the optional [`filter_msg` function from shuffle.py](https://github.com/wazuh/wazuh/blob/a5f51ad61af5abcf49186cd72d4d73c0c3927021/integrations/shuffle.py#L166) to filter events if their rule ID matches any in `SKIP_RULE_IDS`

The variables are built with conditional checks similar to one of the original [slack.py variables](https://github.com/wazuh/wazuh/blob/a5f51ad61af5abcf49186cd72d4d73c0c3927021/integrations/slack.py#L159), so that it will attempt to find the correct key and value, otherwise defaulting to 'N/A' or skipping that key entirely if it's absent. This is to avoid [KeyErrors](https://docs.python.org/3/library/exceptions.html#KeyError) for missing keys in arbitrary JSON structures.


## Update ossec.conf

You'll need to append one or more `<integration>` sections to `/var/ossec/etc/ossec.conf`, that includes the integration name, webhook, and any filters or options.

This section can have multiple entries utilizing the same integration. The sample below is ready to use after modifying or removing the necessary values for your use case. It's written so you can append it directly to `ossec.conf`.

```xml
<ossec_config>
  <integration>
    <name>custom-discord</name>
    <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXX</hook_url>
    <group>GROUP</group> <!-- Replace with an optional comma separated list of groups or remove it -->
    <rule_id>RULE_ID</rule_id> <!-- Replace with an optional comma separated list of rule ids or remove it -->
    <level>SEVERITY_LEVEL</level> <!-- Replace with an optional minimum severity level or remove it -->
    <event_location>EVENT_LOCATION</event_location> <!-- Replace with an optional comma separated list of event locations or remove it -->
    <alert_format>json</alert_format>
    <options>JSON</options> <!-- Replace with your custom JSON object or remove it -->
  </integration>
  <integration>
    <name>custom-discord</name>
    <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXX</hook_url>
    <group>GROUP</group> <!-- Replace with an optional comma separated list of groups or remove it -->
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```


### Examples

Sysmon alert with networking information:

<img src=./media/wazuh_integration_discord_1.png width="440" />

Many file integrity monitoring events caused by package upgrades or Windows updates will be level 7 or lower. Settting the group to `syscheck` and a minimum severity level of `8` will forward anything out of the ordinary to your alert channel.

```xml
  <integration>
    <name>custom-discord</name>
    <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXX</hook_url>
    <group>syscheck</group>
    <level>8</level>
    <alert_format>json</alert_format>
  </integration>
```

Receive an alert for all authentications, Windows logons, or `sudo` / PAM privilege escalations (high volume, try to limit to certain assets):

```xml
  <integration>
    <name>custom-discord</name>
    <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXX</hook_url>
    <group>authentication_success</group>
    <alert_format>json</alert_format>
  </integration>
```

Generic behavior often produces logs lower than severity level 6. Alerting on levels `6` or higher of `sysmon`, `windows_security` and `audit` logs can help point to an initial compromise or foothold.

```xml
  <integration>
    <name>custom-discord</name>
    <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXX</hook_url>
    <group>sysmon,windows_security,audit</group>
    <level>6</level>
    <alert_format>json</alert_format>
  </integration>
```


## Install

Install both files with permissions `0750` owned by `root:wazuh` under:

- `/var/ossec/integrations/custom-discord`
- `/var/ossec/integrations/custom-discord.py`

Then restart wazuh-manager.service.

```bash
sudo systemctl restart wazuh-manager
```


## Debugging

**IMPORTANT**:

> When debugging using raw JSON logs, be sure to copy JSON data from the "Dashboard" view, instead of the "Events" view. You'll see the entire JSON structure is prepended with a few fields, including "_source". This will break the variables in the script, as Wazuh already "sees" those keys as metaFields and parses them correctly when using the script on its own.

You can manually test the python script in debugging mode by copying it to your current directory, then uncommenting the extra `#LOG_FILE =` line, swapping it in for the other one above it. Run with:

```bash
python3 ./custom-discord.py 'test.json' '' '<webhook>' 'debug'
```

Where test.json is a file containing a single log entry (it does not have to be a single line, just one log entry) for testing purposes. Debug output will be writting to `./integrations.log` in the current directory.


## License

This port maintains the same [GPL-2.0](https://github.com/wazuh/wazuh/blob/master/LICENSE#L64) license as the original scripts.
