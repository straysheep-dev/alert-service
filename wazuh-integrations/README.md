# wazuh integrations

This is a custom integration for shipping alerts to Discord via an embed / webhook.

Examples of this [already](https://github.com/eugenio-chaves/eugenio-chaves.github.io/blob/main/blog/2022/creating-a-custom-wazuh-integration/index.md#customizing-the-script) [exist](https://github.com/maikroservice/wazuh-integrations/blob/main/discord/custom-discord.py), making great points of reference to build and revise your own integration. However this port does a few things differently.

- Uses the existing [slack.py `generate_msg`](https://github.com/wazuh/wazuh/blob/a5f51ad61af5abcf49186cd72d4d73c0c3927021/integrations/slack.py#L132) function's code formatting with conditional fields
- Adds conditional fields that will be included with certain Sysmon events
- Includes the optional [`filter_msg` function from shuffle.py](https://github.com/wazuh/wazuh/blob/a5f51ad61af5abcf49186cd72d4d73c0c3927021/integrations/shuffle.py#L166) to filter events if their rule ID matches any in `SKIP_RULE_IDS`

The biggest change however is updating the variables to work when arbitrary JSON structures are present in logs, such as when the `_source` field is prepended. This seems to be the case not just when using custom decoder files, rules, or logging sources, but in general. [A post on the elasticsearch forum details resolving this issue (happening in the dashboard view in that case) by declaring `_source` as a metaField variable in Kibana](https://discuss.elastic.co/t/decode-json-in--source-into-fields/92137), however a comparible option doesn't seem to be present in Wazuh's built in settings, as the issue is not with the dashboard interpreting log content. Searching the docs for the term `metaField` or `_source` only returns [mentioning of the health check options](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/config-file.html#checks-metafields) and [various results containing JSON log samples showing a `_source` field](https://documentation.wazuh.com/current/search.html?q=_source&check_keywords=yes&area=default). This will need reviewed, but for now having examples of the logic required for conditonal variables will be useful if rewriting or expanding them is ever necessary.

The variables are built with conditional checks similar to one of the original [slack.py variables](https://github.com/wazuh/wazuh/blob/a5f51ad61af5abcf49186cd72d4d73c0c3927021/integrations/slack.py#L159), so that it will attempt to find the correct key and value, otherwise defaulting to 'N/A' or skipping that key entirely if it's absent.


## Update Wazuh Conf

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


## Install

Install both files with permissions `0750` owned by `root:wazuh` under:

- `/var/ossec/integrations/custom-discord`
- `/var/ossec/integrations/custom-discord.py`

Then restart wazuh-manager.service.

```bash
sudo systemctl restart wazuh-manager
```


## Debugging

You can manually test the python script in debugging mode by copying it to your current directory, then uncommenting the extra `#LOG_FILE =` line, swapping it in for the other one above it. Run with:

```bash
python3 ./custom-discord.py 'test.json' '' '<webhook>' 'debug'
```

Where test.json is a file containing a single log entry (it does not have to be a single line, just one log entry) for testing purposes. Debug output will be writting to `./integrations.log` in the current directory.